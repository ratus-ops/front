const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const AdmZip = require("adm-zip");

exports.login = async (req, res) => {
    const { username, password } = req.body;

    try {
        const [users] = await db.execute("SELECT * FROM users WHERE username = ?", [username]);
        if (users.length === 0) {
            return res.status(401).json({ message: "Identifiants invalides" });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: "Identifiants invalides" });
        }

        const previousUpdate = user.updated_at; // <-- ici la valeur avant maj

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        // ✅ Mettre à jour updated_at
        await db.execute("UPDATE users SET updated_at = NOW() WHERE id = ?", [user.id]);

        // ✅ Retourner le token + ancienne date
        res.json({
            token,
            updated_at: previousUpdate
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erreur serveur" });
    }
};


exports.dashboard = async (req, res) => {
    try {
        // Total global
        const [totalLicenses] = await db.execute("SELECT * FROM licenses");
        const [totalCards] = await db.execute("SELECT * FROM cards");
        const [totalDomaines] = await db.execute("SELECT * FROM domaines");
        const [[{ totalMoney }]] = await db.execute("SELECT SUM(amount) as totalMoney FROM gains");

        // 5 derniers achats + montant total par license
        const [lastBuy] = await db.execute(`
            SELECT 
                l.*, 
                COALESCE(SUM(g.amount), 0) as amount
            FROM licenses l
            LEFT JOIN gains g ON g.license_id = l.id
            GROUP BY l.id
            ORDER BY l.date DESC
            LIMIT 5
        `);

        res.json({
            cards: {
                totalLicenses,
                totalCards,
                totalDomaines,
                totalMoney,
            },
            lastBuy,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erreur serveur" });
    }
};



exports.users = async (req, res) => {
    try {
        // Récupère toutes les licenses avec leur nombre de cartes associées
        const [licenses] = await db.execute(`
      SELECT 
        l.*, 
        COUNT(c.id) AS cards_count
      FROM licenses l
      LEFT JOIN cards c ON c.license_id = l.id
      GROUP BY l.id
      ORDER BY l.date DESC
    `);

        // Pour chaque license, récupérer les domaines associés
        for (const license of licenses) {
            const [domaines] = await db.execute(
                "SELECT * FROM domaines WHERE license_id = ?",
                [license.id]
            );
            license.domaines = domaines.map(d => d.domaine_name || d.created_at); // adapte selon tes colonnes
        }

        res.json(licenses);
    } catch (error) {
        console.error("Erreur dans le controller users:", error);
        res.status(500).json({ message: "Erreur serveur" });
    }
};

exports.updateUsers = async (req, res) => {
    const { id } = req.params;
    const { username, telegram_id, license_name, license_key, domaines_nbrs } = req.body;

    try {
        await db.execute(
            `
      UPDATE licenses
      SET username = ?, telegram_id = ?, license_name = ?, license_key = ?, domaines_nbrs = ?
      WHERE id = ?
    `,
            [username, telegram_id, license_name, license_key, domaines_nbrs, id]
        );

        res.json({ message: "License mise à jour" });
    } catch (error) {
        console.error("Erreur updateLicense:", error);
        res.status(500).json({ message: "Erreur serveur" });
    }
};


exports.cards = async (req, res) => {
    try {
        const [cards] = await db.execute("SELECT * FROM cards");
        res.json(cards); // ✅ retourne juste le tableau
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erreur serveur" });
    }
};


exports.getLicenses = async (req, res) => {

    try {
        const [licenses] = await db.execute("SELECT * FROM licenses ORDER BY date DESC LIMIT 5");
        res.json(licenses); // PAS { licenses }

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erreur serveur" });
    }

};

function generateLicenseKey() {
    return (
        Math.random().toString(36).substring(3, 9) +
        "-" +
        Math.random().toString(36).substring(3, 9) +
        "-" +
        Math.random().toString(36).substring(3, 9)
    ).toUpperCase();
}


exports.newLicense = async (req, res) => {
    const { username, telegramId, license, domainesNbrs, amount } = req.body;

    try {
        const [existing] = await db.execute(
            `SELECT id FROM licenses WHERE license_name = ? AND (username = ? OR telegram_id = ?)`,
            [license, username, telegramId]
        );

        if (existing.length > 0) {
            return res.status(400).json({ message: "Cette license est déjà attribuée à cet utilisateur ou Telegram ID." });
        }

        const licenseKey = generateLicenseKey();
        const [result] = await db.execute(
            "INSERT INTO licenses (username, telegram_id, license_name, license_key, domaines_nbrs, date) VALUES (?, ?, ?, ?, ?, NOW())",
            [username, telegramId, license, licenseKey, domainesNbrs]
        );

        const [gains] = await db.execute(
            "INSERT INTO gains (license_id, amount, date) VALUES (?, ?, NOW())",
            [result.insertId, amount]
        );

        const [licenseData] = await db.execute("SELECT * FROM licenses WHERE id = ?", [result.insertId]);
        const licenseInfo = licenseData[0];

        const templateDir = path.join(__dirname, "..", "templates", license);
        const configPath = path.join(templateDir, "configs.json");

        if (!fs.existsSync(configPath)) {
            return res.status(500).json({ message: "Fichier de configuration introuvable." });
        }

        const zip = new AdmZip();

        // Ajouter tous les fichiers sauf configs.json
        fs.readdirSync(templateDir).forEach(file => {
            const fullPath = path.join(templateDir, file);
            if (file !== "configs.json") {
                zip.addLocalFile(fullPath);
            }
        });

        // Injecter la license_key dans une version modifiée du configs.json
        const configRaw = fs.readFileSync(configPath, "utf-8");
        const configJSON = JSON.parse(configRaw);
        configJSON.license = licenseKey;

        zip.addFile("configs.json", Buffer.from(JSON.stringify(configJSON, null, 2)));

        // Créer et enregistrer le zip
        const buildDir = path.join(__dirname, "..", "build");
        if (!fs.existsSync(buildDir)) fs.mkdirSync(buildDir);

        const zipFileName = `${telegramId}_${license}.zip`;
        const zipPath = path.join(buildDir, zipFileName);
        zip.writeZip(zipPath);

        res.json({
            message: "License ajoutée avec succès",
            license: licenseInfo,
        });

    } catch (error) {
        console.error("Erreur lors de la création de la license :", error);
        res.status(500).json({ message: "Erreur serveur" });
    }
};

exports.getLicenseNames = async (req, res) => {
    try {
        const [rows] = await db.execute("SELECT DISTINCT license_name FROM licenses");
        const names = rows.map(r => r.license_name).filter(Boolean);
        res.json(names);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erreur serveur" });
    }
};

exports.sendAds = async (req, res) => {
    const botToken = process.env.BOT_TOKEN;
    const { message, target, test, image } = req.body;

    if (!message || !target) {
        return res.status(400).json({ message: "Message et cible requis" });
    }

    try {
        let telegramIds = [];

        if (test) {
            telegramIds = [process.env.TEST_CHAT_ID];
        } else {
            let query = "SELECT DISTINCT telegram_id FROM licenses WHERE telegram_id IS NOT NULL";
            let params = [];

            if (target !== "all") {
                query += " AND license_name = ?";
                params.push(target);
            }

            const [rows] = await db.execute(query, params);
            telegramIds = rows.map(row => row.telegram_id);
        }

        let successCount = 0;

        for (const chatId of telegramIds) {
            try {
                if (image) {
                    try {
                        // 1. Extraction du base64
                        const base64Data = image.split(";base64,").pop();

                        // 2. Création d'un fichier temporaire
                        const tempDir = path.join(__dirname, "../temp");
                        if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir); // crée le dossier s'il n'existe pas

                        const tempFilePath = path.join(tempDir, `image_${Date.now()}.png`);
                        fs.writeFileSync(tempFilePath, base64Data, { encoding: 'base64' });

                        // 3. Préparation du formulaire multipart
                        const formData = new FormData();
                        formData.append("chat_id", chatId);
                        formData.append("caption", message);
                        formData.append("photo", fs.createReadStream(tempFilePath));

                        // 4. Envoi à Telegram
                        await fetch(`https://api.telegram.org/bot${botToken}/sendPhoto`, {
                            method: "POST",
                            body: formData,
                            headers: formData.getHeaders()
                        });

                        // 5. Nettoyage
                        fs.unlinkSync(tempFilePath);

                    } catch (err) {
                        console.error("Erreur lors de l'envoi de l'image à Telegram:", err);
                    }
                } else {
                    // Gestion du message texte simple
                    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                        method: "POST",
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            chat_id: chatId,
                            text: message
                        })
                    });
                }

                successCount++;

            } catch (err) {
                console.error(`Erreur d’envoi à ${chatId}:`, err.message);
            }
        }

        return res.json({
            message: `Message envoyé à ${successCount} utilisateur${successCount > 1 ? "s" : ""}.`,
            touched: successCount
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erreur serveur." });
    }
};


exports.getSettings = async (req, res) => {

    try {
        const [allLicenses] = await db.execute("SELECT * FROM licenses");

        res.json({ allLicenses });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erreur serveur" });
    }

};

exports.editPassword = async (req, res) => {
    const userId = req.user?.userId; // dépend de ton middleware d'auth
    const { password } = req.body;

    if (!userId || !password) {
        return res.status(400).json({ message: "Requête invalide" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?", [hashedPassword, userId]);
        res.json({ message: "Mot de passe mis à jour" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erreur serveur" });
    }

};

exports.downloadDb = async (req, res) => {
    const filename = `dump-${Date.now()}.sql`;
    const dumpCommand = `mysqldump -u${process.env.DB_USER} -p${process.env.DB_PASSWORD} ${process.env.DB_NAME}`;

    exec(dumpCommand, (err, stdout, stderr) => {
        if (err) {
            console.error('Erreur export SQL:', err);
            return res.status(500).send("Erreur export SQL");
        }

        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

        res.send(stdout);
    });
};