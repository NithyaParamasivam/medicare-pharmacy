
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

// CORS
app.use(cors({
    origin: [
        "http://127.0.0.1:5501",
        "http://localhost:5501"
    ],
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
    name: "medicare.sid",
    secret: process.env.SESSION_SECRET || "medicare-session-change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Frontend
app.use(express.static(path.join(__dirname, "frontend")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "frontend", "index.html"));
});

// Check backend and database
app.get("/api/status", async (req, res) => {
    try {
        await db.query("SELECT 1");
        res.json({
            success: true,
            message: "MediCare backend and database connected"
        });
    } catch (error) {
        console.error("Database status error:", error.message);
        res.status(500).json({
            success: false,
            message: "Database connection failed"
        });
    }
});

// REGISTER
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Name, email and password are required"
            });
        }

        if (String(password).length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 6 characters"
            });
        }

        const normalizedEmail = String(email).trim().toLowerCase();

        const [existingUsers] = await db.query(
            "SELECT id FROM users WHERE email = ?",
            [normalizedEmail]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: "Email already registered"
            });
        }

        const cleanName = String(name).trim();
        const hashedPassword = await bcrypt.hash(String(password), 10);

        const [result] = await db.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [cleanName, normalizedEmail, hashedPassword]
        );

        req.session.user = {
            id: result.insertId,
            name: cleanName,
            email: normalizedEmail
        };

        req.session.save((error) => {
            if (error) {
                console.error("Register session error:", error.message);
                return res.status(500).json({
                    success: false,
                    message: "Account created, but session could not be saved. Please log in."
                });
            }

            res.status(201).json({
                success: true,
                message: "Registration successful",
                user: req.session.user
            });
        });
    } catch (error) {
        console.error("Register error:", error.message);
        res.status(500).json({
            success: false,
            message: "Registration failed"
        });
    }
});

// LOGIN
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required"
            });
        }

        const normalizedEmail = String(email).trim().toLowerCase();

        const [users] = await db.query(
            "SELECT id, name, email, password, role FROM users WHERE email = ?",
            [normalizedEmail]
        );

        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        const user = users[0];
        const storedPassword = String(user.password);
        let passwordMatches = false;

        if (/^\$2[aby]\$/.test(storedPassword)) {
            passwordMatches = await bcrypt.compare(
                String(password),
                storedPassword
            );
        } else {
            // Migrate an existing plain-text password to bcrypt.
            passwordMatches = String(password) === storedPassword;

            if (passwordMatches) {
                const hashedPassword = await bcrypt.hash(
                    String(password),
                    10
                );

                await db.query(
                    "UPDATE users SET password = ? WHERE id = ?",
                    [hashedPassword, user.id]
                );
            }
        }

        if (!passwordMatches) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        req.session.regenerate((error) => {
            if (error) {
                console.error("Session regenerate error:", error.message);
                return res.status(500).json({
                    success: false,
                    message: "Could not create login session"
                });
            }

            req.session.user = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role
};
            req.session.save((saveError) => {
                if (saveError) {
                    console.error("Login session save error:", saveError.message);
                    return res.status(500).json({
                        success: false,
                        message: "Could not save login session"
                    });
                }
res.json({
    success: true,
    message: "Login successful",
    user: req.session.user,
    redirect: req.session.user.role === "admin"
        ? "/admin.html"
        : "/index.html"
});
                
            });
        });
    } catch (error) {
        console.error("Login error:", error.message);
        res.status(500).json({
            success: false,
            message: "Login failed"
        });
    }
});

// CURRENT USER
app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please log in"
        });
    }

    res.json({
        success: true,
        user: req.session.user
    });
});

// LOGOUT
app.post("/api/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error("Logout error:", error.message);
            return res.status(500).json({
                success: false,
                message: "Logout failed"
            });
        }

        res.clearCookie("medicare.sid");
        res.json({
            success: true,
            message: "Logged out successfully"
        });
    });
});

// GET CART
app.get("/api/cart", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Please log in to access your cart"
            });
        }

        const [rows] = await db.query(
            "SELECT cart_data FROM user_carts WHERE user_id = ?",
            [req.session.user.id]
        );

        let cart = [];

        if (rows.length > 0 && rows[0].cart_data) {
            const storedCart = rows[0].cart_data;

            cart = typeof storedCart === "string"
                ? JSON.parse(storedCart)
                : storedCart;

            if (!Array.isArray(cart)) {
                cart = [];
            }
        }

        res.json({
            success: true,
            cart
        });
    } catch (error) {
        console.error("Get cart error:", error.message);
        res.status(500).json({
            success: false,
            message: "Could not load cart"
        });
    }
});

// SAVE CART
app.put("/api/cart", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Please log in to save your cart"
            });
        }

        const cart = req.body.cart;

        if (!Array.isArray(cart)) {
            return res.status(400).json({
                success: false,
                message: "Cart must be an array"
            });
        }

        await db.query(
            `INSERT INTO user_carts (user_id, cart_data)
             VALUES (?, ?)
             ON DUPLICATE KEY UPDATE
             cart_data = VALUES(cart_data),
             updated_at = CURRENT_TIMESTAMP`,
            [req.session.user.id, JSON.stringify(cart)]
        );

        res.json({
            success: true,
            message: "Cart saved successfully",
            cart
        });
    } catch (error) {
        console.error("Save cart error:", error.message);
        res.status(500).json({
            success: false,
            message: "Could not save cart"
        });
    }
});

// PLACE ORDER
app.post("/api/orders", async (req, res) => {
    let connection;
    let transactionStarted = false;

    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Please log in before placing an order"
            });
        }

        const {
            fullName,
            phone,
            address,
            city,
            pincode,
            landmark,
            paymentMethod
        } = req.body || {};

        const deliveryName = String(fullName || "").trim();
        const deliveryPhone = String(phone || "").trim();
        const deliveryAddress = String(address || "").trim();
        const deliveryCity = String(city || "").trim();
        const deliveryPincode = String(pincode || "").trim();
        const deliveryLandmark = String(landmark || "").trim();
        const payment = String(paymentMethod || "COD").trim().toUpperCase();

        if (
            !deliveryName ||
            !/^[0-9]{10}$/.test(deliveryPhone) ||
            !deliveryAddress ||
            !deliveryCity ||
            !/^[0-9]{6}$/.test(deliveryPincode)
        ) {
            return res.status(400).json({
                success: false,
                message: "Enter a valid name, 10-digit phone number, address, city and 6-digit pincode"
            });
        }

        // UPI is unavailable until a real payment gateway is integrated.
        if (payment !== "COD") {
            return res.status(400).json({
                success: false,
                message: "Online payment is not available yet. Please choose Cash on Delivery."
            });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();
        transactionStarted = true;

        const userId = req.session.user.id;

        const [cartRows] = await connection.query(
            "SELECT cart_data FROM user_carts WHERE user_id = ? FOR UPDATE",
            [userId]
        );

        if (cartRows.length === 0 || !cartRows[0].cart_data) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(400).json({
                success: false,
                message: "Your cart is empty"
            });
        }

        let cart = cartRows[0].cart_data;

        if (typeof cart === "string") {
            cart = JSON.parse(cart);
        }

        if (!Array.isArray(cart) || cart.length === 0) {
            await connection.rollback();
            transactionStarted = false;

            return res.status(400).json({
                success: false,
                message: "Your cart is empty"
            });
        }

        let totalAmount = 0;
        const items = [];

        for (const item of cart) {
            const name = String(item.name || "").trim();
            const price = Number(item.price);
            const quantity = Number(item.quantity);

            if (
                !name ||
                !Number.isFinite(price) ||
                price < 0 ||
                !Number.isInteger(quantity) ||
                quantity < 1
            ) {
                await connection.rollback();
                transactionStarted = false;

                return res.status(400).json({
                    success: false,
                    message: "Invalid medicine details in cart"
                });
            }

            const subtotal = Math.round(price * quantity * 100) / 100;
            totalAmount += subtotal;

            items.push({
                name,
                type: String(item.type || ""),
                image: String(item.image || ""),
                price,
                quantity,
                subtotal
            });
        }

        totalAmount = Math.round(totalAmount * 100) / 100;

        // Save order and delivery details
        const [orderResult] = await connection.query(
            `INSERT INTO orders
             (user_id, total_amount, status, delivery_name, phone,
              delivery_address, city, pincode, landmark, payment_method)
             VALUES (?, ?, 'Placed', ?, ?, ?, ?, ?, ?, ?)`,
            [
                userId,
                totalAmount,
                deliveryName,
                deliveryPhone,
                deliveryAddress,
                deliveryCity,
                deliveryPincode,
                deliveryLandmark || null,
                payment
            ]
        );

        const orderId = orderResult.insertId;

        // Save all order items
        for (const item of items) {
            await connection.query(
                `INSERT INTO order_items
                 (order_id, medicine_name, medicine_type, image,
                  price, quantity, subtotal)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    orderId,
                    item.name,
                    item.type,
                    item.image,
                    item.price,
                    item.quantity,
                    item.subtotal
                ]
            );
        }

        console.log("\n========== NEW ORDER ==========");
        console.log("Order ID:", orderId);
        console.log("Customer ID:", userId);
        console.log("Customer Name:", deliveryName);
        console.log("Phone Number:", deliveryPhone);
        console.log("Delivery Address:", deliveryAddress);
        console.log("City:", deliveryCity);
        console.log("Pincode:", deliveryPincode);
        console.log("Landmark:", deliveryLandmark || "Not provided");
        console.log("Payment Method:", payment);
        console.log("Total Amount: ₹", totalAmount);

        console.log("---------- ORDER ITEMS ----------");

        for (const item of items) {
            console.log(
                `Medicine: ${item.name} | Quantity: ${item.quantity} | Price: ₹${item.price} | Subtotal: ₹${item.subtotal}`
            );
        }

        console.log("================================\n");

        // Clear cart after order is saved
        await connection.query(
            "DELETE FROM user_carts WHERE user_id = ?",
            [userId]
        );

        await connection.commit();
        transactionStarted = false;

        res.status(201).json({
            success: true,
            message: "Order placed successfully",
            orderId,
            totalAmount
        });
    } catch (error) {
        if (connection && transactionStarted) {
            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error("Rollback error:", rollbackError.message);
            }
        }

        console.error("Place order error:", error.message);

        res.status(500).json({
            success: false,
            message: "Could not place order"
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// GET ALL ORDERS - ADMIN ONLY
app.get("/api/orders", requireAdmin, async (req, res) => {
    try {
        const [orders] = await db.query(
    `SELECT
        o.id,
        o.user_id,
        o.total_amount,
        o.status,
        o.created_at,
        o.delivery_name,
        o.phone,
        o.delivery_address,
        o.city,
        o.pincode,
        o.landmark,
        o.payment_method,
        u.name AS customer_name,
        u.email AS customer_email
     FROM orders o
     LEFT JOIN users u ON u.id = o.user_id
     ORDER BY o.created_at DESC`
);

        for (const order of orders) {
            const [items] = await db.query(
                `SELECT medicine_name, medicine_type, image,
                        price, quantity, subtotal
                 FROM order_items
                 WHERE order_id = ?
                 ORDER BY id ASC`,
                [order.id]
            );

            order.items = items;
        }

        res.json({
            success: true,
            orders
        });
    } catch (error) {
        console.error("Get all orders error:", error.message);

        res.status(500).json({
            success: false,
            message: "Could not load orders"
        });
    }
});
// GET ONE ORDER
app.get("/api/orders/:id", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Please log in to view this order"
            });
        }

        const orderId = Number(req.params.id);

        if (!Number.isInteger(orderId) || orderId < 1) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID"
            });
        }

        const [orders] = await db.query(
            `SELECT id, total_amount, status, created_at,
                    delivery_name, phone, delivery_address,
                    city, pincode, landmark, payment_method
             FROM orders
             WHERE id = ? AND user_id = ?`,
            [orderId, req.session.user.id]
        );

        if (orders.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Order not found"
            });
        }

        const [items] = await db.query(
            `SELECT medicine_name, medicine_type, image,
                    price, quantity, subtotal
             FROM order_items
             WHERE order_id = ?
             ORDER BY id ASC`,
            [orderId]
        );

        res.json({
            success: true,
            order: {
                ...orders[0],
                items
            }
        });
    } catch (error) {
        console.error("Get order details error:", error.message);
        res.status(500).json({
            success: false,
            message: "Could not load order details"
        });
    }
});

/* CUSTOMER CANCEL ORDER */
app.put("/api/orders/:id/cancel", async (req, res) => {
    try {
        // Login check
        if (!req.session.user) {
            return res.status(401).json({
                success: false,
                message: "Please log in first"
            });
        }

        const orderId = Number(req.params.id);
        const userId = req.session.user.id;

        if (!Number.isInteger(orderId) || orderId < 1) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID"
            });
        }

        // Cancel only this user's Placed/Processing order
        const [result] = await db.query(
            `UPDATE orders
             SET status = 'Cancelled'
             WHERE id = ?
               AND user_id = ?
               AND status IN ('Placed', 'Processing')`,
            [orderId, userId]
        );

        if (result.affectedRows === 0) {
            const [rows] = await db.query(
                "SELECT status FROM orders WHERE id = ? AND user_id = ?",
                [orderId, userId]
            );

            if (rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Order not found"
                });
            }

            return res.status(409).json({
                success: false,
                message: "This order cannot be cancelled because it is no longer awaiting processing."
            });
        }

        return res.json({
            success: true,
            message: "Order cancelled successfully",
            orderId,
            status: "Cancelled"
        });

    } catch (error) {
        console.error("Cancel order error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Could not cancel order"
        });
    }
});


// JSON error handler
app.use((error, req, res, next) => {
    console.error("Server error:", error.message);

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        success: false,
        message: "Internal server error"
    });
});

// ADMIN-ONLY MIDDLEWARE
function requireAdmin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please login first"
        });
    }

    if (req.session.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Admin access only"
        });
    }

    next();
}



// UPDATE ORDER STATUS
app.put("/api/orders/:id/status", requireAdmin, async (req, res) => {
    try {
        const orderId = Number(req.params.id);
        const { status } = req.body;

        const allowedStatuses = [
            "Placed",
            "Processing",
            "Shipped",
            "Delivered",
            "Cancelled"
        ];

        if (!Number.isInteger(orderId) || orderId < 1) {
            return res.status(400).json({
                success: false,
                message: "Invalid order ID"
            });
        }

        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({
                success: false,
                message: "Invalid order status"
            });
        }

        const [result] = await db.query(
            "UPDATE orders SET status = ? WHERE id = ?",
            [status, orderId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: "Order not found"
            });
        }

        res.json({
            success: true,
            message: "Order status updated successfully",
            orderId,
            status
        });
    } catch (error) {
        console.error("Update order status error:", error.message);

        res.status(500).json({
            success: false,
            message: "Could not update order status"
        });
    }
});

/* DEMO: Automatically update order delivery status */
async function autoUpdateOrderStatuses() {
    try {
        // Move orders to Shipped after 2 minutes
        await db.query(
            `UPDATE orders
             SET status = 'Shipped'
             WHERE status IN ('Placed', 'Processing')
             AND created_at <= DATE_SUB(NOW(), INTERVAL  1 DAY)`
        );

        // Move orders to Delivered after 4 minutes
        await db.query(
            `UPDATE orders
             SET status = 'Delivered'
             WHERE status = 'Shipped'
             AND created_at <= DATE_SUB(NOW(), INTERVAL 3 DAY)`
        );
    } catch (error) {
        console.error("Automatic delivery update error:", error.message);
    }
}

setInterval(autoUpdateOrderStatuses, 60000);
autoUpdateOrderStatuses();


// START SERVER
app.listen(PORT, () => {
    console.log(`MediCare Pharmacy server running at http://localhost:${PORT}`);
});
