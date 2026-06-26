const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config(); // Laad de variabelen uit het .env bestand
const { createMollieClient } = require('@mollie/api-client');
const saltRounds = 10; // Standaard en veilige waarde voor bcrypt
const app = express();
const port = 3000;

// Zorg ervoor dat de 'uploads' map bestaat
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

app.use(express.json());
app.use(express.static(__dirname)); // Serveert je HTML, CSS, JS bestanden
app.use('/uploads', express.static(uploadsDir)); // Serveer de geüploade bestanden

// --- Mollie Client Setup ---
const mollieClient = createMollieClient({ apiKey: process.env.MOLLIE_API_KEY });

// --- Multer (File Upload) Setup ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, 'uploads/') },
    filename: function (req, file, cb) { cb(null, Date.now() + path.extname(file.originalname)) }
});
const upload = multer({ storage: storage });

// --- Session Setup ---
app.use(session({
    store: new FileStore({}), // Slaat sessies op in een 'sessions' map
    secret: process.env.SESSION_SECRET, // Gebruik de variabele
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
    }
}));


// --- Database Setup (SQLite) ---
const db = new sqlite3.Database('./lumiere.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the lumiere database.');
    // Maak een tabel voor gebruikers als deze nog niet bestaat
    // Voeg email en status toe (member, elite)
    db.run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, status TEXT NOT NULL DEFAULT "member", reset_token TEXT, reset_token_expires INTEGER)');
    // Maak een tabel voor betalingen
    db.run('CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY, amount INTEGER, status TEXT, user_email TEXT, product_name TEXT)');
    // Maak een tabel voor producten
    db.run('CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, price INTEGER NOT NULL, category TEXT NOT NULL DEFAULT "ordinary", animation_type TEXT, image_url TEXT)');
    // Maak een tabel voor de wishlist
    db.run('CREATE TABLE IF NOT EXISTS wishlist(user_id INTEGER NOT NULL, product_id INTEGER NOT NULL, PRIMARY KEY (user_id, product_id))');
});

// --- API Endpoints ---

// Gebruikersregistratie
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Naam, e-mail en wachtwoord zijn verplicht.' });
    }

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.error("Bcrypt error: ", err);
            return res.status(500).json({ error: 'Kon wachtwoord niet verwerken.' });
        }

        const sql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
        db.run(sql, [name, email, hash], function(err) {
            if (err) {
                console.error(err);
                return res.status(400).json({ error: 'Deze naam of e-mail is al in gebruik.' });
            }
            const newUser = { id: this.lastID, name: name, email: email, status: 'member' };
            req.session.user = newUser;
            res.status(201).json(newUser);
        });
    });
});

// Gebruikerslogin
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'E-mail en wachtwoord zijn verplicht.' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.get(sql, [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Ongeldige e-mail of wachtwoord.' });
        }

        // Vergelijk het opgegeven wachtwoord met de opgeslagen hash
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                // Wachtwoord komt overeen
                // Maak een nieuw object zonder het wachtwoord om terug te sturen en in de sessie op te slaan
                const userSessionData = { id: user.id, name: user.name, email: user.email, status: user.status };
                req.session.user = userSessionData; // Sla gebruiker op in de sessie
                res.status(200).json(userSessionData);
            } else {
                // Wachtwoord komt niet overeen
                res.status(401).json({ error: 'Ongeldige e-mail of wachtwoord.' });
            }
        });
    });
});

// Gebruiker uitloggen
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Kon niet uitloggen.' });
        }
        res.clearCookie('connect.sid'); // Verwijder de sessie-cookie
        res.status(200).json({ message: 'Succesvol uitgelogd.' });
    });
});

// --- Wachtwoord Vergeten Flow ---

// 1. Vraag een reset aan
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) {
            // Stuur altijd een succes-achtig bericht om te voorkomen dat e-mailadressen worden geraden
            return res.status(200).json({ message: 'Als dit e-mailadres in ons systeem bestaat, is er een herstellink verzonden.' });
        }

        const token = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000; // 1 uur

        db.run('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?', [token, expires, email], async (err) => {
            if (err) {
                return res.status(500).json({ error: 'Fout bij het aanmaken van de herstellink.' });
            }
            await sendPasswordResetEmail(email, token);
            res.status(200).json({ message: 'Als dit e-mailadres in ons systeem bestaat, is er een herstellink verzonden.' });
        });
    });
});

// 2. Reset het wachtwoord
app.post('/api/reset-password', (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) {
        return res.status(400).json({ error: 'Token en nieuw wachtwoord zijn verplicht.' });
    }

    const sql = 'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?';
    db.get(sql, [token, Date.now()], (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Wachtwoordherstel-token is ongeldig of verlopen.' });
        }

        bcrypt.hash(password, saltRounds, (err, hash) => {
            if (err) {
                return res.status(500).json({ error: 'Kon wachtwoord niet verwerken.' });
            }

            // Update wachtwoord en verwijder de token
            const updateSql = 'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?';
            db.run(updateSql, [hash, user.id], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Kon wachtwoord niet bijwerken.' });
                }
                res.status(200).json({ message: 'Wachtwoord succesvol gereset. U kunt nu inloggen.' });
            });
        });
    });
});

// --- Product API ---
app.get('/api/products', (req, res) => {
    db.all('SELECT * FROM products', [], (err, rows) => {
        if (err) {
            console.error("Error fetching products:", err);
            return res.status(500).json({ error: 'Kon producten niet ophalen.' });
        }
        res.json(rows);
    });
});

// --- My Account API ---
app.get('/api/my-orders', requireLogin, (req, res) => {
    const userEmail = req.session.user.email;
    db.all('SELECT id, product_name, amount, status FROM payments WHERE user_email = ? ORDER BY id DESC', [userEmail], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Kon bestelgeschiedenis niet ophalen.' });
        }
        res.json(rows);
    });
});

// --- Wishlist API ---
app.get('/api/wishlist', requireLogin, (req, res) => {
    db.all('SELECT product_id FROM wishlist WHERE user_id = ?', [req.session.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Kon wishlist niet ophalen.' });
        res.json(rows.map(r => r.product_id));
    });
});

app.post('/api/wishlist', requireLogin, (req, res) => {
    const { productId } = req.body;
    db.run('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)', [req.session.user.id, productId], (err) => {
        if (err) return res.status(500).json({ error: 'Kon product niet toevoegen aan wishlist.' });
        res.status(201).json({ message: 'Product toegevoegd aan wishlist.' });
    });
});

app.delete('/api/wishlist/:productId', requireLogin, (req, res) => {
    const { productId } = req.params;
    db.run('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?', [req.session.user.id, productId], function(err) {
        if (err) return res.status(500).json({ error: 'Kon product niet verwijderen uit wishlist.' });
        if (this.changes === 0) return res.status(404).json({ error: 'Product niet gevonden in wishlist.' });
        res.status(200).json({ message: 'Product verwijderd uit wishlist.' });
    });
});


// Update user name
app.put('/api/user/update-name', requireLogin, (req, res) => {
    const { name } = req.body;
    const userId = req.session.user.id;

    if (!name) {
        return res.status(400).json({ error: 'Naam is verplicht.' });
    }

    db.run('UPDATE users SET name = ? WHERE id = ?', [name, userId], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ error: 'Deze naam is al in gebruik.' });
            }
            return res.status(500).json({ error: 'Kon naam niet bijwerken.' });
        }
        req.session.user.name = name;
        res.status(200).json({ message: 'Naam succesvol bijgewerkt.', user: req.session.user });
    });
});

// Update user password
app.put('/api/user/update-password', requireLogin, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.session.user.id;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Huidig en nieuw wachtwoord zijn verplicht.' });
    }

    db.get('SELECT password FROM users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) {
            return res.status(500).json({ error: 'Kon gebruiker niet vinden.' });
        }

        bcrypt.compare(currentPassword, user.password, (err, result) => {
            if (!result) {
                return res.status(401).json({ error: 'Huidige wachtwoord is onjuist.' });
            }

            bcrypt.hash(newPassword, saltRounds, (err, hash) => {
                db.run('UPDATE users SET password = ? WHERE id = ?', [hash, userId]);
                res.status(200).json({ message: 'Wachtwoord succesvol bijgewerkt.' });
            });
        });
    });
});


// --- Mollie Betaalsysteem ---

// 1. Start een betaling en krijg een Mollie URL
app.post('/api/create-payment', async (req, res) => {
    const { amount, userEmail, productName } = req.body;
    if (!amount || !userEmail || !productName) {
        return res.status(400).json({ error: 'Bedrag, e-mail en productnaam zijn verplicht.' });
    }

    try {
        const internalOrderId = `ORD-${Date.now()}`;

        const payment = await mollieClient.payments.create({
            amount: {
                currency: 'EUR',
                value: (amount / 100).toFixed(2), // Mollie verwacht een string zoals "10.00"
            },
            description: `Bestelling ${internalOrderId}: ${productName}`,
            redirectUrl: `${process.env.BASE_URL}/`, // Gebruik de basis-URL
            webhookUrl: `${process.env.BASE_URL}/api/mollie-webhook`, // Gebruik de basis-URL
            metadata: {
                internalOrderId: internalOrderId,
                userEmail: userEmail,
                productName: productName
            },
            method: ["bancontact", "kbc", "belfius", "ideal"] // Specificeer Belgische/Nederlandse methoden
        });

        // Sla de bestelling op in de database met de Mollie payment ID
        const sql = 'INSERT INTO payments (id, amount, status, user_email, product_name) VALUES (?, ?, ?, ?, ?)';
        db.run(sql, [payment.id, amount, 'pending', userEmail, productName], (err) => {
            if (err) {
                console.error("Database error after creating Mollie payment:", err);
                return res.status(500).json({ error: 'Kon bestelling niet opslaan na aanmaken betaling.' });
            }
            // Stuur de Mollie checkout URL terug naar de frontend
            res.status(201).json({ checkoutUrl: payment.getCheckoutUrl() });
        });

    } catch (error) {
        console.error("Mollie API error:", error);
        res.status(500).json({ error: 'Kon betaling niet aanmaken bij Mollie.' });
    }
});

// 2. Mollie Webhook: Ontvang statusupdates van Mollie
app.post('/api/mollie-webhook', async (req, res) => {
    const paymentId = req.body.id;

    try {
        const payment = await mollieClient.payments.get(paymentId);

        if (payment.isPaid()) {
            // Betaling is geslaagd!
            await handleSuccessfulPayment(payment.id, payment.metadata.productName, payment.metadata.userEmail, payment.amount.value);
        } else if (payment.isFailed() || payment.isCanceled() || payment.isExpired()) {
            // Betaling is mislukt
            db.run('UPDATE payments SET status = ? WHERE id = ?', [payment.status, payment.id]);
        }

        res.status(200).send(); // Stuur een 200 OK terug naar Mollie
    } catch (error) {
        console.error("Webhook error:", error);
        res.status(500).send();
    }
});

// Hulpfunctie om een geslaagde betaling af te handelen
async function handleSuccessfulPayment(paymentId, productName, userEmail, amountValue) {
    db.run('UPDATE payments SET status = ? WHERE id = ?', ['succeeded', paymentId], async (err) => {
        if (err) return;

        // Als het een Elite Membership is, upgrade de gebruiker
        if (productName === 'Elite Membership') {
            db.run('UPDATE users SET status = "elite" WHERE email = ?', [userEmail]);
        }
        // Stuur een bevestigingsmail
        const amountInCents = Math.round(parseFloat(amountValue) * 100);
        await sendPurchaseConfirmation(userEmail, amountInCents, paymentId);
    });
}

// 3. Controleer de status van een betaling (optioneel, voor frontend feedback)
app.get('/api/payment-status/:id', (req, res) => {
    const paymentId = req.params.id;
    const sql = 'SELECT status FROM payments WHERE id = ?';
    db.get(sql, [paymentId], (err, row) => {
        if (err || !row) {
            return res.status(404).json({ error: 'Betaling niet gevonden.' });
        }
        res.json({ status: row.status });
    });
});

// --- Admin Panel Endpoints ---

// 1. Haal alle betalingen op (voor de admin)
app.get('/api/admin/payments', requireAdmin, (req, res) => {
    db.all('SELECT * FROM payments ORDER BY id DESC', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Kon betalingen niet ophalen.' });
        }
        res.json(rows);
    });
});

// 2. Update de status van een betaling (blijft nuttig voor handmatige correcties)
app.post('/api/admin/update-payment-status', requireAdmin, (req, res) => {
    const { paymentId, status } = req.body;
    if (!paymentId || !status) {
        return res.status(400).json({ error: 'Payment ID en status zijn verplicht.' });
    }

    db.get('SELECT * FROM payments WHERE id = ?', [paymentId], (err, payment) => {
        if (err || !payment) {
            return res.status(404).json({ error: 'Betaling niet gevonden.' });
        }

        db.run('UPDATE payments SET status = ? WHERE id = ?', [status, paymentId], async function(err) {
            if (err) {
                return res.status(500).json({ error: 'Kon status niet updaten.' });
            }

            // Als de betaling is goedgekeurd en het een Elite Membership is, upgrade de gebruiker
            if (status === 'succeeded' && payment.product_name === 'Elite Membership') {
                db.run('UPDATE users SET status = "elite" WHERE email = ?', [payment.user_email]);
                // Optioneel: stuur een bevestigingsmail
                await sendPurchaseConfirmation(payment.user_email, payment.amount, payment.id);
            }
            res.status(200).json({ message: 'Status succesvol bijgewerkt.' });
        });
    });
});

// --- Admin Product Management ---
app.post('/api/admin/products', requireAdmin, upload.single('image'), (req, res) => {
    const { name, description, price, category, animation_type } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const sql = 'INSERT INTO products (name, description, price, category, animation_type, image_url) VALUES (?, ?, ?, ?, ?, ?)';
    db.run(sql, [name, description, price, category, animation_type, imageUrl], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Kon product niet toevoegen.' });
        }
        res.status(201).json({ id: this.lastID, ...req.body, image_url: imageUrl });
    });
});

app.put('/api/admin/products/:id', requireAdmin, upload.single('image'), (req, res) => {
    const { name, description, price, category, animation_type } = req.body;
    let imageUrl = req.body.existing_image_url || null; // Behoud de oude afbeelding als er geen nieuwe is
    if (req.file) {
        imageUrl = `/uploads/${req.file.filename}`;
    }
    const sql = 'UPDATE products SET name = ?, description = ?, price = ?, category = ?, animation_type = ?, image_url = ? WHERE id = ?';
    db.run(sql, [name, description, price, category, animation_type, imageUrl, req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Kon product niet bijwerken.' });
        }
        res.status(200).json({ message: 'Product succesvol bijgewerkt.' });
    });
});

app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => {
    const product = await new Promise((resolve, reject) => {
        db.get('SELECT image_url FROM products WHERE id = ?', [req.params.id], (err, row) => err ? reject(err) : resolve(row));
    });

    db.run('DELETE FROM products WHERE id = ?', [req.params.id], function (err) {
        if (err) {
            return res.status(500).json({ error: 'Kon product niet verwijderen.' });
        }
        // Verwijder de afbeelding van de server als deze bestaat
        if (product && product.image_url) {
            const imagePath = path.join(__dirname, product.image_url);
            fs.unlink(imagePath, (unlinkErr) => {
                if (unlinkErr) console.error("Kon afbeelding niet verwijderen:", unlinkErr);
            });
        }
        res.status(200).json({ message: 'Product succesvol verwijderd.' });
    });
});

// --- E-mail Systeem (met Nodemailer) ---
// LET OP: Dit is een voorbeeldconfiguratie. Gebruik voor een echte applicatie
// een service als SendGrid/Mailgun of je eigen SMTP-server.
// Voor dit voorbeeld gebruiken we een 'ethereal' testaccount.
async function sendPurchaseConfirmation(toEmail, amount, paymentId) {
    // Maak een testaccount aan op Ethereal
    let testAccount = await nodemailer.createTestAccount();

    let transporter = nodemailer.createTransport({
        host: "smtp.ethereal.email",
        port: 587,
        secure: false,
        auth: {
            user: testAccount.user,
            pass: testAccount.pass,
        },
    });

    let info = await transporter.sendMail({
        from: '"LUMIÈRE Shop" <noreply@lumiere.com>',
        to: toEmail,
        subject: "Bedankt voor je aankoop!",
        html: `<b>Bedankt voor je bestelling!</b><br>Je betaling van €${amount / 100} is geslaagd.<br>Betalings-ID: ${paymentId}`,
    });

    console.log("Message sent: %s", info.messageId);
    // Preview URL wordt in de console gelogd.
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}

async function sendPasswordResetEmail(toEmail, token) {
    let testAccount = await nodemailer.createTestAccount();

    let transporter = nodemailer.createTransport({
        host: "smtp.ethereal.email",
        port: 587,
        secure: false,
        auth: {
            user: testAccount.user,
            pass: testAccount.pass,
        },
    });

    const resetLink = `${process.env.BASE_URL}/reset-password?token=${token}`;

    let info = await transporter.sendMail({
        from: '"LUMIÈRE Shop" <noreply@lumiere.com>',
        to: toEmail,
        subject: "Wachtwoord resetten voor LUMIÈRE",
        html: `<b>Wachtwoord resetten</b><br>U ontvangt dit omdat u (of iemand anders) een wachtwoordreset heeft aangevraagd voor uw account.<br>
               Klik op de volgende link, of plak deze in uw browser om het proces te voltooien:<br>
               <a href="${resetLink}">${resetLink}</a><br>
               Als u dit niet heeft aangevraagd, negeer dan deze e-mail en uw wachtwoord blijft ongewijzigd.`,
    });

    console.log("Password reset email sent: %s", info.messageId);
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}

// --- Middleware voor paginabeveiliging ---
const requireLogin = (req, res, next) => {
    if (req.session.user) {
        next(); // Gebruiker is ingelogd, ga door
    } else {
        // Gebruiker is niet ingelogd, stuur naar de homepage
        res.redirect('/');
    }
};

const requireElite = (req, res, next) => {
    if (req.session.user && req.session.user.status === 'elite') {
        next(); // Gebruiker is elite, ga door
    } else {
        // Gebruiker is geen elite, stuur naar de homepage
        res.redirect('/');
    }
};

const requireAdmin = (req, res, next) => {
    // Voor nu maken we de eerste gebruiker (ID 1) de admin.
    // In een echt systeem zou je een 'status' kolom gebruiken.
    if (req.session.user && req.session.user.status === 'admin') {
        next(); // Gebruiker is admin, ga door
    } else {
        res.status(403).redirect('/'); // Geen toegang, stuur naar home
    }
};

// --- Pagina's serveren ---
app.get('/members', requireLogin, (req, res) => {
    res.sendFile(__dirname + '/members_collection.html');
});

app.get('/elite', requireElite, (req, res) => { // Voeg de 'requireElite' middleware hier toe
    res.sendFile(__dirname + '/elite_collection.html');
});

app.get('/reset-password', (req, res) => {
    res.sendFile(__dirname + '/reset_password.html');
});

app.get('/admin', requireAdmin, (req, res) => {
    res.sendFile(__dirname + '/admin.html');
});

app.get('/my-account', requireLogin, (req, res) => {
    res.sendFile(__dirname + '/my_account.html');
});

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/lumi_re_premium_shop.html');
});

app.listen(port, () => {
    console.log(`Lumière server draait op http://localhost:${port}`);
});