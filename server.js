const express = require("express");
const mssql = require("mssql");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const sql = require("mssql");
const jwt = require("jsonwebtoken"); // Thư viện tạo Token

const app = express();
app.use(express.json());
app.use(cors());

// Thêm avt
const multer = require("multer");
const path = require("path");

// Cấu hình cho phép FE truy cập vào thư mục uploads để lấy ảnh hiện lên web
app.use("/uploads", express.static("uploads"));

// Cấu hình "máy quét" Multer: Lưu ảnh vào đâu, tên file là gì?
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Lưu vào thư mục uploads vừa tạo
  },
  filename: function (req, file, cb) {
    // Đổi tên file thành thời gian hiện tại để không bao giờ bị trùng tên
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

// ==========================================
// BỘ MIDDLEWARE PHÂN QUYỀN
// ==========================================
const JWT_SECRET = process.env.JWT_SECRET || "KNDFOOD_SECRET_KEY";

// 1. Kiểm tra Token (Bắt buộc phải có để lấy req.user)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ message: "Vui lòng đăng nhập!" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Phiên đăng nhập đã hết hạn!" });
        req.user = user;
        next();
    });
};

// 2. STAFF & ADMIN
const isAdminOrStaff = (req, res, next) => {
    const userRole = req.user.role ? req.user.role.toUpperCase() : ''; // Ép kiểu chữ hoa để không bị lỗi
    if (userRole === 'ADMIN' || userRole === 'STAFF') {
        next(); // Cho phép đi tiếp vào trang quản trị
    } else {
        res.status(403).json({ message: "Bạn không có quyền truy cập!" });
    }
};

// 3. CHỈ ADMIN MỚI ĐƯỢC VÀO
const isAdmin = (req, res, next) => {
    const userRole = req.user.role ? req.user.role.toUpperCase() : '';
    if (userRole === 'ADMIN') {
        next(); 
    } else {
        res.status(403).json({ message: "Chỉ Quản trị viên mới có quyền này!" });
    }
};

// 1. Cấu hình
const config = {
  user: "sa",
  password: "Luxxie29@",
  server: "YUNGLUXX",
  database: "KNDFOOD",
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
  port: 1433,
};

// 2. Khởi tạo một Pool kết nối độc lập (Cách này an toàn 100%)
const pool = new mssql.ConnectionPool(config);
const poolConnect = pool
  .connect()
  .then(() => console.log("✅ Đã kết nối thành công tới SQL Server!"))
  .catch((err) => console.error("❌ Lỗi kết nối Database: ", err));

// ==========================================
// 3. API DÀNH CHO REACT
// ==========================================

// API Đăng ký tài khoản mới
app.post("/api/register", async (req, res) => {
  try {
    const { FullName, Email, Password } = req.body;
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(Password, saltRounds);

    await poolConnect;
    await pool
      .request()
      .input("FullName", mssql.NVarChar, FullName)
      .input("Email", mssql.VarChar, Email)
      .input("PasswordHash", mssql.VarChar, hashedPassword)
      .input("Role", mssql.VarChar, "User").query(`
                INSERT INTO Users (FullName, Email, PasswordHash, Role) 
                VALUES (@FullName, @Email, @PasswordHash, @Role)
            `);

    res.status(201).json({ message: "Đăng ký thành công!" });
  } catch (err) {
    console.error("Lỗi đăng ký: ", err);
    if (err.number === 2627) {
      return res.status(400).json({ message: "Email này đã được sử dụng!" });
    }
    res.status(500).json({ message: "Lỗi Server" });
  }
});

// Chỉ Admin/Staff mới xem được danh sách User
app.get("/api/users", authenticateToken, isAdminOrStaff, async (req, res) => {
  try {
    await poolConnect;
    // Bổ sung thêm Avatar, Username, Bio vào danh sách hiển thị cho Admin
    const result = await pool
      .request()
      .query(
        "SELECT UserID, FullName, Email, Username, Bio, Avatar, Role, CreatedAt FROM Users",
      );

    res.json(result.recordset);
  } catch (err) {
    console.error("Lỗi khi lấy User: ", err);
    res.status(500).json({ error: err.message });
  }
});

// API ĐĂNG NHẬP TK
app.post("/api/login", async (req, res) => {
  try {
    const { Email, Password } = req.body;
    await poolConnect;

    const result = await pool
      .request()
      .input("Email", mssql.VarChar, Email)
      .query("SELECT * FROM Users WHERE Email = @Email");

    const user = result.recordset[0];

    if (!user) {
      return res
        .status(400)
        .json({ message: "Email hoặc Mật khẩu không chính xác!" });
    }

    const isMatch = await bcrypt.compare(Password, user.PasswordHash);

    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "Email hoặc Mật khẩu không chính xác!" });
    }

    // TẠO TOKEN ĐỂ KIỂM TRA QUYỀN
    const token = jwt.sign(
      { userId: user.UserID, role: user.Role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // Đăng nhập thành công! THÊM AVT, USERNAME, BIO để FE lưu LocalStorage
    res.json({
      message: `Chào mừng ${user.FullName} trở lại!`,
      token: token, // <-- Gửi token về cho React lưu lại
      user: {
        UserID: user.UserID,
        FullName: user.FullName,
        Email: user.Email,
        Role: user.Role,
        Avatar: user.Avatar, 
        Username: user.Username, 
        Bio: user.Bio, 
      },
    });
  } catch (err) {
    console.error("Lỗi đăng nhập: ", err);
    res.status(500).json({ message: "Lỗi Server" });
  }
});

// API XÓA NGƯỜI DÙNG
app.delete("/api/users/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    await poolConnect;

    const result = await pool
      .request()
      .input("UserID", mssql.Int, userId)
      .query("DELETE FROM Users WHERE UserID = @UserID");

    if (result.rowsAffected[0] === 0) {
      return res
        .status(404)
        .json({ message: "Không tìm thấy người dùng này để xóa!" });
    }

    res.json({ message: "Đã xóa người dùng thành công!" });
  } catch (err) {
    console.error("Lỗi khi xóa User: ", err);
    res.status(500).json({ message: "Lỗi Server không thể xóa!" });
  }
});

// ==========================================
// API ADMIN CẬP NHẬT VAI TRÒ
// ==========================================
app.put("/api/admin/update-role", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId, newRole } = req.body;
    console.log("Đang đổi quyền cho ID:", userId, "Thành:", newRole); 

    if (!userId || !newRole) {
      return res.status(400).json({ message: "Thiếu thông tin!" });
    }

    // Thực hiện truy vấn
    const result = await pool.request()
      .input("UserID", sql.Int, parseInt(userId)) // Ép kiểu về số cho chắc
      .input("Role", sql.NVarChar, newRole)
      .query(`
        UPDATE Users 
        SET Role = @Role 
        WHERE UserID = @UserID
      `);

    if (result.rowsAffected[0] === 0) {
        return res.status(404).json({ message: "Không tìm thấy người dùng để cập nhật!" });
    }

    res.status(200).json({ message: "Cập nhật thành công!" });

  } catch (error) {
    console.error("LỖI SQL CHI TIẾT:", error.message); 
    res.status(500).json({ message: "Lỗi máy chủ không thể cập nhật vai trò." });
  }
});

// ==========================================
// API CẬP NHẬT THÔNG TIN CÁ NHÂN 
// ==========================================
app.put("/api/users/update", async (req, res) => {
  try {
    const { UserID, FullName, Email, Username, Bio } = req.body;
    await poolConnect;

    await pool
      .request()
      .input("UserID", mssql.Int, UserID)
      .input("FullName", mssql.NVarChar, FullName)
      .input("Email", mssql.VarChar, Email)
      .input("Username", mssql.VarChar, Username)
      .input("Bio", mssql.NVarChar, Bio)
      .query(`
                UPDATE Users 
                SET FullName = @FullName, 
                    Email = @Email,
                    Username = @Username,
                    Bio = @Bio
                WHERE UserID = @UserID
            `);

    res.json({ message: "Cập nhật thành công!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Lỗi Server khi cập nhật hồ sơ" });
  }
});

// API ĐỔI MẬT KHẨU
app.put("/api/users/change-password", async (req, res) => {
  try {
    const { UserID, CurrentPassword, NewPassword } = req.body;
    await poolConnect;

    const result = await pool
      .request()
      .input("UserID", mssql.Int, UserID)
      .query("SELECT PasswordHash FROM Users WHERE UserID = @UserID");

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "Không tìm thấy người dùng!" });
    }

    const user = result.recordset[0];
    const isMatch = await bcrypt.compare(CurrentPassword, user.PasswordHash);
    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "Mật khẩu hiện tại không chính xác!" });
    }

    const saltRounds = 10;
    const hashedNewPassword = await bcrypt.hash(NewPassword, saltRounds);

    await pool
      .request()
      .input("UserID", mssql.Int, UserID)
      .input("NewPasswordHash", mssql.VarChar, hashedNewPassword)
      .query(
        "UPDATE Users SET PasswordHash = @NewPasswordHash WHERE UserID = @UserID",
      );

    res.json({ message: "Đổi mật khẩu thành công!" });
  } catch (err) {
    console.error("Lỗi khi đổi mật khẩu:", err);
    res.status(500).json({ message: "Lỗi Server không thể đổi mật khẩu!" });
  }
});

// API UPLOAD AVATAR
app.post(
  "/api/users/upload-avatar",
  upload.single("avatar"),
  async (req, res) => {
    try {
      const userId = req.body.UserID;

      if (!req.file) {
        return res.status(400).json({ message: "Vui lòng chọn một ảnh!" });
      }

      const avatarUrl = `http://localhost:5000/uploads/${req.file.filename}`;

      await poolConnect;
      await pool
        .request()
        .input("Avatar", mssql.NVarChar, avatarUrl)
        .input("UserID", mssql.Int, userId)
        .query("UPDATE Users SET Avatar = @Avatar WHERE UserID = @UserID");

      res.json({
        message: "Cập nhật ảnh đại diện thành công!",
        avatarUrl: avatarUrl,
      });
    } catch (err) {
      console.error("Lỗi khi upload ảnh:", err);
      res.status(500).json({ message: "Lỗi Server không thể lưu ảnh!" });
    }
  },
);

// ==========================================
// API QUÊN MẬT KHẨU (CHỈ GỬI MAIL & LƯU TOKEN)
// ==========================================
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { Email } = req.body;

    if (!Email) {
      return res.status(400).json({ message: "Vui lòng cung cấp email." });
    }

    // 1. KIỂM TRA EMAIL TRONG DB
    const userResult = await pool
      .request()
      .input("Email", sql.NVarChar, Email)
      .query("SELECT * FROM Users WHERE Email = @Email");

    if (userResult.recordset.length === 0) {
      return res
        .status(200)
        .json({ message: "Nếu email hợp lệ, liên kết đã được gửi!" });
    }

    // 2. TẠO TOKEN NGẪU NHIÊN
    const token = crypto.randomBytes(32).toString("hex");

    // 3. CHỈ LƯU TOKEN VÀ THỜI GIAN HẾT HẠN VÀO DATABASE (Đồng bộ GETDATE)
    await pool
      .request()
      .input("Token", sql.NVarChar, token)
      .input("Email", sql.NVarChar, Email).query(`
        UPDATE Users 
        SET ResetPasswordToken = @Token, 
            ResetTokenExpiry = DATEADD(minute, 15, GETDATE()) 
        WHERE Email = @Email
      `);

    // 4. CẤU HÌNH VÀ GỬI EMAIL
    const resetLink = `http://localhost:5173/reset-password?token=${token}&email=${Email}`;

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "lekhanhlux29@gmail.com",
        pass: "fzkrdfkqkvyobtkh", // MẬT KHẨU ỨNG DỤNG
      },
    });

    const mailOptions = {
      from: '"CSKH KND Food" <lekhanhlux29@gmail.com>',
      to: Email,
      subject: "[KND Food] Yêu cầu đặt lại mật khẩu",
      html: `
        <div style='font-family: Arial, sans-serif; padding: 20px; color: #333;'>
          <h2 style='color: #f97316;'>Xin chào!</h2>
          <p>Bạn vừa yêu cầu đặt lại mật khẩu cho tài khoản tại Website KND Food.</p>
          <p>Vui lòng click vào nút bên dưới để tạo mật khẩu mới. Liên kết này chỉ có hiệu lực trong vòng <b>15 phút</b>.</p>
          <br/>
          <a href='${resetLink}' style='display: inline-block; padding: 12px 24px; background-color: #f97316; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;'>
            Đổi Mật Khẩu
          </a>
          <br/><br/>
          <p>Nếu bạn không yêu cầu thay đổi mật khẩu, vui lòng bỏ qua email này.</p>
          <hr style='border: 1px solid #eee; margin: 20px 0;'/>
          <p style='font-size: 12px; color: #777;'>Trân trọng!<br/>Đội ngũ CSKH KND Food</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Liên kết đặt lại mật khẩu đã được gửi!" });
  } catch (error) {
    console.error("Lỗi API Quên mật khẩu:", error);
    res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
});

// ==========================================
// API ĐỔI MẬT KHẨU MỚI
// ==========================================
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    console.log("🔍 React gửi lên:", { email, token });

    if (!email || !token || !newPassword) {
      return res.status(400).json({ message: "Thiếu thông tin bắt buộc!" });
    }

    // 1. Kiểm tra Token
    const checkResult = await pool
      .request()
      .input("Email", sql.NVarChar, email)
      .input("Token", sql.NVarChar, token).query(`
        SELECT * FROM Users 
        WHERE Email = @Email 
          AND ResetPasswordToken = @Token 
          AND ResetTokenExpiry > GETDATE()
      `);

    if (checkResult.recordset.length === 0) {
      return res
        .status(400)
        .json({ message: "Đường dẫn không hợp lệ hoặc đã hết hạn!" });
    }

    // 2. Mã hóa mật khẩu
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // 3. Cập nhật vào DB
    await pool
      .request()
      .input("Password", sql.NVarChar, hashedPassword)
      .input("Email", sql.NVarChar, email).query(`
        UPDATE Users 
        SET PasswordHash = @Password,  -- TÊN CỘT CHUẨN ĐÂY RỒI
            ResetPasswordToken = NULL, 
            ResetTokenExpiry = NULL 
        WHERE Email = @Email
      `);

    res.status(200).json({ message: "Đổi mật khẩu thành công!" });
  } catch (error) {
    console.error("Lỗi API Đổi mật khẩu:", error);
    res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
});

// ==========================================
// API TẠO CÔNG THỨC MỚI (CÓ THÔNG BÁO CHO STAFF)
// ==========================================
app.post("/api/recipes/create", upload.any(), async (req, res) => {
  const transaction = new mssql.Transaction(pool);

  try {
    await poolConnect;
    await transaction.begin();

    const {
      UserID,
      Title,
      Description,
      CategoryID,
      Difficulty,
      PrepTime,
      CookTime,
      Servings,
      VideoUrl,
    } = req.body;

    const ingredients = JSON.parse(req.body.ingredients);
    const stepsDescriptions = JSON.parse(req.body.stepsDescriptions);

    // Xử lý ảnh bìa
    const mainImageFile = req.files.find((f) => f.fieldname === "mainImage");
    const mainImageUrl = mainImageFile
      ? `http://localhost:5000/uploads/${mainImageFile.filename}`
      : null;

    // --- Xử lý VIDEO ---
    let finalVideoUrl = null;
    const mainVideoFile = req.files.find((f) => f.fieldname === "mainVideo");

    if (mainVideoFile) {
      finalVideoUrl = `http://localhost:5000/uploads/${mainVideoFile.filename}`;
    } else if (VideoUrl && VideoUrl.trim() !== "") {
      finalVideoUrl = VideoUrl.trim();
    }

    // 1. Thêm vào bảng Recipes
    const request = new mssql.Request(transaction);
    const resultRecipe = await request
      .input("UserID", mssql.Int, UserID)
      .input("CategoryID", mssql.Int, CategoryID)
      .input("Title", mssql.NVarChar, Title)
      .input("Description", mssql.NVarChar, Description)
      .input("ImageURL", mssql.NVarChar, mainImageUrl)
      .input("VideoURL", mssql.NVarChar, finalVideoUrl)
      .input("PrepTime", mssql.Int, PrepTime || 0)
      .input("CookTime", mssql.Int, CookTime || 0)
      .input("Servings", mssql.Int, Servings || 1)
      .input("Difficulty", mssql.NVarChar, Difficulty).query(`
                INSERT INTO Recipes (UserID, CategoryID, Title, Description, ImageURL, VideoURL, PrepTime, CookTime, Servings, Difficulty, Status)
                OUTPUT INSERTED.RecipeID
                VALUES (@UserID, @CategoryID, @Title, @Description, @ImageURL, @VideoURL, @PrepTime, @CookTime, @Servings, @Difficulty, 'Pending')
            `);

    const newRecipeId = resultRecipe.recordset[0].RecipeID;

    // 2. Thêm vào bảng Ingredients
    for (let ing of ingredients) {
      const reqIng = new mssql.Request(transaction);
      await reqIng
        .input("RecipeID", mssql.Int, newRecipeId)
        .input("IngredientName", mssql.NVarChar, ing.name)
        .input("Quantity", mssql.NVarChar, ing.amount)
        .input("Unit", mssql.NVarChar, ing.unit).query(`
                    INSERT INTO Ingredients (RecipeID, IngredientName, Quantity, Unit)
                    VALUES (@RecipeID, @IngredientName, @Quantity, @Unit)
                `);
    }

    // 3. Thêm vào bảng RecipeSteps
    for (let i = 0; i < stepsDescriptions.length; i++) {
      const stepFile = req.files.find((f) => f.fieldname === `stepImage_${i}`);
      const stepImageUrl = stepFile
        ? `http://localhost:5000/uploads/${stepFile.filename}`
        : null;

      const reqStep = new mssql.Request(transaction);
      await reqStep
        .input("RecipeID", mssql.Int, newRecipeId)
        .input("StepNumber", mssql.Int, i + 1)
        .input("Instruction", mssql.NVarChar, stepsDescriptions[i])
        .input("ImageURL", mssql.NVarChar, stepImageUrl).query(`
                    INSERT INTO RecipeSteps (RecipeID, StepNumber, Instruction, ImageURL)
                    VALUES (@RecipeID, @StepNumber, @Instruction, @ImageURL)
                `);
    }

    // ============================================================
    // 4. LOGIC GỬI THÔNG BÁO CHO STAFF & ADMIN
    // ============================================================
    // Lấy danh sách tất cả những người có quyền duyệt bài
    const staffReq = new mssql.Request(transaction);
    const staffUsers = await staffReq.query("SELECT UserID FROM Users WHERE Role IN ('Admin', 'Staff')");
    
    const notifyMsg = `Có món ăn mới: "${Title}" đang chờ bạn phê duyệt.`;
    
    for (let staff of staffUsers.recordset) {
        const notifyStaffReq = new mssql.Request(transaction);
        await notifyStaffReq
            .input("StaffID", mssql.Int, staff.UserID)
            .input("Msg", mssql.NVarChar, notifyMsg)
            .query(`
                INSERT INTO Notifications (UserID, Message, Type, Link, IsRead, CreatedAt)
                VALUES (@StaffID, @Msg, 'System', '/admin', 0, GETDATE())
            `);
    }
// ============================================================
    await transaction.commit();
    res.status(201).json({ message: "Đăng công thức thành công, đang chờ duyệt!" });
  } catch (err) {
    console.error("LỖI GỐC TỪ SQL:", err.message);
    try {
      await transaction.rollback();
    } catch (rollbackErr) { }

    res.status(500).json({ message: "Lỗi Server: " + err.message });
  }
});

// ==========================================
// API LẤY DANH SÁCH TẤT CẢ MÓN ĂN (CHỈ LẤY MÓN ĐÃ DUYỆT)
// ==========================================
app.get("/api/recipes", async (req, res) => {
  try {
    await poolConnect;
    const request = new mssql.Request(pool);

    const result = await request.query(`
    SELECT 
        r.RecipeID, r.Title, r.ImageURL, r.Difficulty,
        r.PrepTime, r.CookTime, r.CategoryID, u.FullName,
        ISNULL(c.AverageRating, 0) AS AverageRating,
        ISNULL(c.ReviewCount, 0) AS ReviewCount
    FROM Recipes r
    LEFT JOIN Users u ON r.UserID = u.UserID
    LEFT JOIN (
        SELECT 
            RecipeID, 
            AVG(CAST(Rating AS FLOAT)) AS AverageRating, 
            COUNT(CommentID) AS ReviewCount
        FROM Comments
        GROUP BY RecipeID
    ) c ON r.RecipeID = c.RecipeID
    WHERE r.Status = 'Approved' OR r.Status IS NULL
    ORDER BY r.RecipeID DESC
`);

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error("Lỗi lấy danh sách món ăn:", err);
    res.status(500).json({ message: "Lỗi Server!" });
  }
});

// ==========================================
// API LẤY DANH SÁCH CÔNG THỨC CỦA 1 USER
// ==========================================
app.get("/api/recipes/user/:userId", async (req, res) => {
  try {
    await poolConnect;
    const request = pool.request();
    request.input("UserID", mssql.Int, req.params.userId);

    const result = await request.query(`
            SELECT RecipeID, Title, ImageURL, Difficulty, PrepTime, CookTime, Status 
            FROM Recipes 
            WHERE UserID = @UserID 
            ORDER BY RecipeID DESC
        `);

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error("Lỗi khi lấy danh sách bài đăng:", err);
    res.status(500).json({ message: "Lỗi Server không thể lấy dữ liệu!" });
  }
});

// ==========================================
// API LẤY CHI TIẾT MỘT MÓN ĂN
// ==========================================
app.get("/api/recipes/detail/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await poolConnect;

    const recipeReq = pool.request();
    recipeReq.input("RecipeID", mssql.Int, id);
    const recipeResult = await recipeReq.query(`
            SELECT r.*, u.FullName, u.Avatar, u.Username
            FROM Recipes r
            LEFT JOIN Users u ON r.UserID = u.UserID
            WHERE r.RecipeID = @RecipeID
        `);

    if (recipeResult.recordset.length === 0) {
      return res.status(404).json({ message: "Không tìm thấy món ăn!" });
    }

    let recipe = recipeResult.recordset[0];

    const ingReq = pool.request();
    ingReq.input("RecipeID", mssql.Int, id);
    const ingResult = await ingReq.query(
      `SELECT * FROM Ingredients WHERE RecipeID = @RecipeID`,
    );
    recipe.ingredients = ingResult.recordset;

    const stepReq = pool.request();
    stepReq.input("RecipeID", mssql.Int, id);
    const stepResult = await stepReq.query(
      `SELECT * FROM RecipeSteps WHERE RecipeID = @RecipeID ORDER BY StepNumber ASC`,
    );
    recipe.steps = stepResult.recordset;

    res.status(200).json(recipe);
  } catch (err) {
    console.error("Lỗi lấy chi tiết món ăn:", err);
    res.status(500).json({ message: "Lỗi Server!" });
  }
});

// ==========================================
// API SỬA CÔNG THỨC MÓN ĂN
// ==========================================
app.put("/api/recipes/update/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      UserID, Title, Description, PrepTime, CookTime, Servings, Difficulty, CategoryID, ingredients, steps,
    } = req.body;

    await poolConnect;
    const transaction = new mssql.Transaction(pool);
    await transaction.begin();

    try {
      const checkReq = new mssql.Request(transaction);
      checkReq.input("RecipeID", mssql.Int, id);
      const checkRes = await checkReq.query(
        `SELECT UserID FROM Recipes WHERE RecipeID = @RecipeID`,
      );

      if (checkRes.recordset.length === 0)
        throw new Error("Không tìm thấy món ăn");
      if (checkRes.recordset[0].UserID !== UserID)
        throw new Error("Bạn không có quyền sửa món ăn này");

      const updateReq = new mssql.Request(transaction);
      updateReq.input("RecipeID", mssql.Int, parseInt(id) || 0);
      updateReq.input("Title", mssql.NVarChar, String(Title || ""));
      updateReq.input("Description", mssql.NVarChar, String(Description || ""));
      updateReq.input("PrepTime", mssql.Int, parseInt(PrepTime) || 0);
      updateReq.input("CookTime", mssql.Int, parseInt(CookTime) || 0);
      updateReq.input("Servings", mssql.Int, parseInt(Servings) || 0);
      updateReq.input("Difficulty", mssql.Int, parseInt(Difficulty) || 1);
      updateReq.input("CategoryID", mssql.Int, parseInt(CategoryID) || 1);

      await updateReq.query(`
                UPDATE Recipes 
                SET Title = @Title, Description = @Description, PrepTime = @PrepTime, 
                    CookTime = @CookTime, Servings = @Servings, Difficulty = @Difficulty, 
                    CategoryID = @CategoryID, UpdatedAt = GETDATE()
                WHERE RecipeID = @RecipeID
            `);

      const delIngReq = new mssql.Request(transaction);
      delIngReq.input("RecipeID", mssql.Int, id);
      await delIngReq.query(
        `DELETE FROM Ingredients WHERE RecipeID = @RecipeID`,
      );

      if (ingredients && ingredients.length > 0) {
        for (const ing of ingredients) {
          const addIngReq = new mssql.Request(transaction);
          addIngReq.input("RecipeID", mssql.Int, id);
          addIngReq.input("IngredientName", mssql.NVarChar, String(ing.IngredientName || ""));
          addIngReq.input("Quantity", mssql.NVarChar, String(ing.Quantity || ""));
          addIngReq.input("Unit", mssql.NVarChar, String(ing.Unit || ""));

          await addIngReq.query(`
                        INSERT INTO Ingredients (RecipeID, IngredientName, Quantity, Unit) 
                        VALUES (@RecipeID, @IngredientName, @Quantity, @Unit)
                    `);
        }
      }

      const delStepReq = new mssql.Request(transaction);
      delStepReq.input("RecipeID", mssql.Int, id);
      await delStepReq.query(
        `DELETE FROM RecipeSteps WHERE RecipeID = @RecipeID`,
      );

      if (steps && steps.length > 0) {
        for (let i = 0; i < steps.length; i++) {
          const step = steps[i];
          const addStepReq = new mssql.Request(transaction);
          addStepReq.input("RecipeID", mssql.Int, id);
          addStepReq.input("StepNumber", mssql.Int, i + 1);
          addStepReq.input("Instruction", mssql.NVarChar, String(step.Instruction || ""));

          if (step.ImageURL) {
            addStepReq.input("ImageURL", mssql.NVarChar, String(step.ImageURL));
          } else {
            addStepReq.input("ImageURL", mssql.NVarChar, null);
          }

          await addStepReq.query(`
                        INSERT INTO RecipeSteps (RecipeID, StepNumber, Instruction, ImageURL) 
                        VALUES (@RecipeID, @StepNumber, @Instruction, @ImageURL)
                    `);
        }
      }

      await transaction.commit();
      res.status(200).json({ message: "Cập nhật thành công!" });
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  } catch (err) {
    console.error("Lỗi update recipe:", err);
    res.status(500).json({ message: err.message || "Lỗi Server!" });
  }
});

// ==========================================
// API TÌM KIẾM NHANH (MÓN ĂN & NGƯỜI DÙNG)
// ==========================================
app.get("/api/search", async (req, res) => {
  try {
    const searchQuery = req.query.q;

    if (!searchQuery || searchQuery.trim() === "") {
      return res.json({ recipes: [], users: [] });
    }

    const sqlSearchTerm = `%${searchQuery}%`;

    const recipesResult = await pool.request()
      .input("Term", sql.NVarChar, sqlSearchTerm)
      .query(`
        SELECT TOP 5 RecipeID, Title, ImageURL 
        FROM Recipes 
        WHERE Title LIKE @Term AND (Status = 'Approved' OR Status IS NULL)
      `);

    const usersResult = await pool.request()
      .input("Term", sql.NVarChar, sqlSearchTerm)
      .query(`
        SELECT TOP 3 UserID, Username, Avatar 
        FROM Users 
        WHERE Username LIKE @Term OR FullName LIKE @Term
      `);

    res.status(200).json({
      recipes: recipesResult.recordset,
      users: usersResult.recordset
    });

  } catch (error) {
    console.error("Lỗi API Tìm kiếm:", error);
    res.status(500).json({ message: "Lỗi hệ thống" });
  }
});

// ==========================================
// API LẤY THÔNG TIN HỒ SƠ QUA USERNAME
// ==========================================
app.get("/api/users/profile/:username", async (req, res) => {
  try {
    const username = req.params.username;
    const result = await pool.request()
      .input("Username", sql.NVarChar, username)
      .query(`
        SELECT UserID, FullName, Username, Avatar, Bio, Role 
        FROM Users 
        WHERE Username = @Username
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }
    
    res.status(200).json(result.recordset[0]);
  } catch (error) {
    console.error("Lỗi lấy profile:", error);
    res.status(500).json({ message: "Lỗi máy chủ" });
  }
});


// ==========================================
// API DÀNH CHO NHÂN VIÊN DUYỆT BÀI
// ==========================================

// 1. Lấy danh sách món ăn đang chờ duyệt
app.get("/api/admin/pending-recipes", authenticateToken, isAdminOrStaff, async (req, res) => {
    try {
        await poolConnect;
        const result = await pool.request().query(`
            SELECT r.RecipeID, r.Title, r.ImageURL, r.CreatedAt, u.FullName, u.Avatar 
            FROM Recipes r
            LEFT JOIN Users u ON r.UserID = u.UserID
            WHERE r.Status = 'Pending'
            ORDER BY r.RecipeID DESC
        `);
        res.status(200).json(result.recordset);
    } catch (err) {
        console.error("Lỗi lấy bài chờ duyệt:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// 2. Duyệt bài (đổi Status & gửi Thông báo)
app.put("/api/admin/approve-recipe/:id", authenticateToken, isAdminOrStaff, async (req, res) => {
    const transaction = new mssql.Transaction(pool);
    try {
        const { id } = req.params;
        await poolConnect;
        await transaction.begin();

        // A: Lấy thông tin UserID và title của món ăn trước khi duyệt
        const infoReq = new mssql.Request(transaction);
        const infoResult = await infoReq.input("RecipeID", mssql.Int, id)
            .query("SELECT UserID, Title FROM Recipes WHERE RecipeID = @RecipeID");

        if (infoResult.recordset.length === 0) {
            throw new Error("Không tìm thấy món ăn!");
        }
        const { UserID, Title } = infoResult.recordset[0];

        // B: cập nhật trạng thái bài viết
        const updateReq = new mssql.Request(transaction);
        await updateReq.input("RecipeID", mssql.Int, id)
            .query("UPDATE Recipes SET Status = 'Approved' WHERE RecipeID = @RecipeID");

        // C: Tự động gửi thông báo cho chủ bài viết
        const notifyReq = new mssql.Request(transaction);
        const msg = `Chúc mừng! Món "${Title}" của bạn đã được phê duyệt và hiển thị lên trang chủ.`;
        await notifyReq.input("UserID", mssql.Int, UserID)
            .input("Message", mssql.NVarChar, msg)
            .input("Type", mssql.VarChar, 'Approve')
            .input("Link", mssql.VarChar, `/recipe/${id}`)
            .query(`
                INSERT INTO Notifications (UserID, Message, Type, Link, IsRead, CreatedAt)
                VALUES (@UserID, @Message, @Type, @Link, 0, GETDATE())
            `);

        await transaction.commit();
        res.json({ message: "Đã duyệt và gửi thông báo cho người dùng!" });
    } catch (err) {
        await transaction.rollback();
        console.error("Lỗi duyệt bài:", err);
        res.status(500).json({ message: "Lỗi Server: " + err.message });
    }
});

// 3. Từ chối bài (Gửi thông báo trước khi Xóa)
app.delete("/api/admin/reject-recipe/:id", authenticateToken, isAdminOrStaff, async (req, res) => {
    const transaction = new mssql.Transaction(pool);
    try {
        const { id } = req.params;
        await poolConnect;
        await transaction.begin();

        // A: Lấy thông tin để biết gửi thông báo cho ai
        const infoReq = new mssql.Request(transaction);
        const infoResult = await infoReq.input("RecipeID", mssql.Int, id)
            .query("SELECT UserID, Title FROM Recipes WHERE RecipeID = @RecipeID");

        if (infoResult.recordset.length > 0) {
            const { UserID, Title } = infoResult.recordset[0];
            // B: Gửi thông báo lỗi
            const notifyReq = new mssql.Request(transaction);
            const msg = `Rất tiếc! Bài đăng "${Title}" đã bị từ chối do không phù hợp với tiêu chuẩn nội dung.`;
            await notifyReq.input("UserID", mssql.Int, UserID)
                .input("Message", mssql.NVarChar, msg)
                .input("Type", mssql.VarChar, 'Reject')
                .query(`
                    INSERT INTO Notifications (UserID, Message, Type, IsRead, CreatedAt)
                    VALUES (@UserID, @Message, @Type, 0, GETDATE())
                `);
        }

        // C: Xóa dữ liệu (xóa con trước cha)
        await new mssql.Request(transaction).input("RID", mssql.Int, id).query("DELETE FROM Ingredients WHERE RecipeID = @RID");
        await new mssql.Request(transaction).input("RID", mssql.Int, id).query("DELETE FROM RecipeSteps WHERE RecipeID = @RID");
        await new mssql.Request(transaction).input("RID", mssql.Int, id).query("DELETE FROM Recipes WHERE RecipeID = @RID");

        await transaction.commit();
        res.json({ message: "Đã từ chối bài viết và thông báo tới người dùng!" });
    } catch (err) {
        await transaction.rollback();
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// ==========================================
// API: NGƯỜI DÙNG TỰ XÓA BÀI CỦA MÌNH
// ==========================================
app.delete("/api/recipes/delete/:id", authenticateToken, async (req, res) => {
  try {
    const recipeId = req.params.id;
    const userId = req.user.userId; // Lấy ID của người đang đăng nhập từ Token
    const userRole = req.user.role ? req.user.role.toUpperCase() : '';

    await poolConnect;
    const transaction = new mssql.Transaction(pool);
    await transaction.begin();

    try {
      // 1. Kiểm tra xem món ăn có tồn tại ko & ai là tác giả
      const checkReq = new mssql.Request(transaction);
      checkReq.input("RecipeID", mssql.Int, recipeId);
      const checkRes = await checkReq.query("SELECT UserID FROM Recipes WHERE RecipeID = @RecipeID");

      if (checkRes.recordset.length === 0) {
        throw new Error("Không tìm thấy công thức này!");
      }

      // 2. Chặn nếu người xóa không phải là tác giả & ko phải Admin
      if (checkRes.recordset[0].UserID !== userId && userRole !== 'ADMIN') {
        throw new Error("Bạn không có quyền xóa bài của người khác!");
      }

      // 3. Phải xóa dữ liệu con (Nguyên liệu, các bước) trước để không bị lỗi FK
      const deleteIngReq = new mssql.Request(transaction);
      await deleteIngReq.input("RecipeID", mssql.Int, recipeId).query("DELETE FROM Ingredients WHERE RecipeID = @RecipeID");

      const deleteStepReq = new mssql.Request(transaction);
      await deleteStepReq.input("RecipeID", mssql.Int, recipeId).query("DELETE FROM RecipeSteps WHERE RecipeID = @RecipeID");

      // 4. Cuối cùng mới xóa Công thức chính
      const deleteRecipeReq = new mssql.Request(transaction);
      await deleteRecipeReq.input("RecipeID", mssql.Int, recipeId).query("DELETE FROM Recipes WHERE RecipeID = @RecipeID");

      await transaction.commit();
      res.status(200).json({ message: "Đã xóa công thức thành công!" });
      
    } catch (error) {
      await transaction.rollback();
      res.status(403).json({ message: error.message });
    }
  } catch (err) {
    console.error("Lỗi xóa bài:", err);
    res.status(500).json({ message: "Lỗi Server!" });
  }
});

// API: Lấy danh sách thông báo của User
app.get("/api/notifications", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        await poolConnect;
        const result = await pool.request()
            .input("UserID", mssql.Int, userId)
            .query(`
                SELECT * FROM Notifications 
                WHERE UserID = @UserID 
                ORDER BY CreatedAt DESC
            `);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ message: "Lỗi lấy thông báo!" });
    }
});

// API: Đánh dấu đã đọc hết
app.put("/api/notifications/read-all", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        await poolConnect;
        await pool.request()
            .input("UserID", mssql.Int, userId)
            .query("UPDATE Notifications SET IsRead = 1 WHERE UserID = @UserID");
        res.json({ message: "Đã đọc tất cả" });
    } catch (err) {
        res.status(500).json({ message: "Lỗi cập nhật!" });
    }
});

// API: Xóa tất cả thông báo ĐÃ ĐỌC
app.delete("/api/notifications/delete-read", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        await poolConnect;
        
        const result = await pool.request()
            .input("UserID", mssql.Int, userId)
            .query("DELETE FROM Notifications WHERE UserID = @UserID AND IsRead = 1");
            
        res.json({ 
            message: "Đã dọn dẹp thông báo cũ!", 
            deletedCount: result.rowsAffected[0] 
        });
    } catch (err) {
        console.error("Lỗi xóa thông báo:", err);
        res.status(500).json({ message: "Lỗi Server không thể xóa!" });
    }
});

// ============================================
// 1. API LẤY DANH SÁCH BÌNH LUẬN CỦA 1 MÓN ĂN
// ============================================
app.get("/api/comments/recipe/:recipeId", async (req, res) => {
    try {
        const { recipeId } = req.params;
        await poolConnect;
        
        const result = await pool.request()
            .input("RecipeID", mssql.Int, recipeId)
            .query(`
                SELECT 
                    c.*, 
                    u.FullName, 
                    u.Username, 
                    u.Avatar 
                FROM Comments c
                JOIN Users u ON c.UserID = u.UserID
                WHERE c.RecipeID = @RecipeID
                ORDER BY c.CreatedAt DESC
            `);
            
        res.json(result.recordset);
    } catch (err) {
        console.error("Lỗi lấy bình luận:", err);
        res.status(500).json({ message: "Lỗi Server không thể tải bình luận!" });
    }
});

// ==========================================
// 2. API ĐĂNG BÌNH LUẬN MỚI + GỬI THÔNG BÁO
// ==========================================
app.post("/api/comments", authenticateToken, async (req, res) => {
    // 1. LẤY THÊM Rating TỪ FRONTEND GỬI LÊN
    const { RecipeID, Content, Rating } = req.body; 
    const UserID = req.user.userId; // Lấy từ Token đã giải mã

    // 2. BỔ SUNG KIỂM TRA ĐÁNH GIÁ SAO
    if (!Rating || Rating < 1 || Rating > 5) {
        return res.status(400).json({ message: "Vui lòng chọn số sao hợp lệ (từ 1 đến 5)!" });
    }

    if (!Content || Content.trim() === "") {
        return res.status(400).json({ message: "Nội dung bình luận không được để trống!" });
    }

    const transaction = new mssql.Transaction(pool);
    try {
        await poolConnect;
        await transaction.begin();

        // Bước A: Chèn bình luận mới VÀO DB KÈM RATING
        const commentReq = new mssql.Request(transaction);
        const resultComment = await commentReq
            .input("RecipeID", mssql.Int, RecipeID)
            .input("UserID", mssql.Int, UserID)
            .input("Content", mssql.NVarChar, Content)
            .input("Rating", mssql.Int, Rating) // Thêm biến Rating vào SQL
            .query(`
                INSERT INTO Comments (RecipeID, UserID, Content, Rating, CreatedAt)
                OUTPUT INSERTED.*
                VALUES (@RecipeID, @UserID, @Content, @Rating, GETDATE())
            `);

        const newComment = resultComment.recordset[0];

        // Bước B: Lấy thông tin User vừa bình luận (để trả về cho FE hiển thị ngay)
        const userReq = new mssql.Request(transaction);
        const userResult = await userReq
            .input("UID", mssql.Int, UserID)
            .query("SELECT FullName, Username, Avatar FROM Users WHERE UserID = @UID");
        
        const userInfo = userResult.recordset[0];

        // Bước C: GỬI THÔNG BÁO CHO TÁC GIẢ (Nếu người cmt ko phải tác giả)
        const recipeReq = new mssql.Request(transaction);
        const recipeInfo = await recipeReq
            .input("RID", mssql.Int, RecipeID)
            .query("SELECT UserID, Title FROM Recipes WHERE RecipeID = @RID");
        
        const authorID = recipeInfo.recordset[0].UserID;
        const recipeTitle = recipeInfo.recordset[0].Title;

        if (authorID !== UserID) {
            const notifyReq = new mssql.Request(transaction);
            // Sửa lại lời nhắn xíu cho ngầu: "đã đánh giá x sao..."
            const notifyMsg = `${userInfo.FullName} đã đánh giá ${Rating} sao về món "${recipeTitle}" của bạn.`;
            
            await notifyReq
                .input("TargetUID", mssql.Int, authorID)
                .input("Msg", mssql.NVarChar, notifyMsg)
                .input("Link", mssql.NVarChar, `/recipe/${RecipeID}`)
                .query(`
                    INSERT INTO Notifications (UserID, Message, Type, Link, IsRead, CreatedAt)
                    VALUES (@TargetUID, @Msg, 'Comment', @Link, 0, GETDATE())
                `);
        }

        await transaction.commit();

        // Trả về dữ liệu gộp để Frontend update UI không cần load lại trang
        res.status(201).json({
            ...newComment,
            FullName: userInfo.FullName,
            Username: userInfo.Username,
            Avatar: userInfo.Avatar
        });

    } catch (err) {
        if (transaction) await transaction.rollback();
        console.error("Lỗi đăng bình luận:", err);
        res.status(500).json({ message: "Lỗi Server không thể gửi bình luận!" });
    }
});

// API XÓA BÌNH LUẬN (Người viết hoặc Chủ bài viết)
app.delete("/api/comments/:commentId", authenticateToken, async (req, res) => {
    try {
        const { commentId } = req.params;
        const currentUserId = req.user.userId; // ID người đang yêu cầu xóa

        await poolConnect;

        // 1. Lấy thông tin bình luận và chủ bài viết để kiểm tra quyền
        const checkReq = await pool.request()
            .input("CID", mssql.Int, commentId)
            .query(`
                SELECT c.UserID as CommentOwner, r.UserID as RecipeAuthor 
                FROM Comments c
                JOIN Recipes r ON c.RecipeID = r.RecipeID
                WHERE c.CommentID = @CID
            `);

        if (checkReq.recordset.length === 0) {
            return res.status(404).json({ message: "Bình luận không tồn tại!" });
        }

        const { CommentOwner, RecipeAuthor } = checkReq.recordset[0];

        // 2. Kiểm tra: Nếu là chủ cmt hoặc chủ bài thì mới cho xóa
        if (currentUserId === CommentOwner || currentUserId === RecipeAuthor) {
            await pool.request()
                .input("CID", mssql.Int, commentId)
                .query("DELETE FROM Comments WHERE CommentID = @CID");

            return res.json({ message: "Đã xóa bình luận thành công!" });
        } else {
            return res.status(403).json({ message: "Bạn không có quyền xóa bình luận này!" });
        }

    } catch (err) {
        console.error("Lỗi xóa cmt:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});


// ==========================================
  // XỬ LÝ XÓA BÌNH LUẬN DÙNG SWEETALERT
  // ==========================================
  const handleDeleteComment = async (commentId) => {
    // Gọi bảng cảnh báo xịn sò của SweetAlert2
    Swal.fire({
      title: 'Xóa bình luận?',
      text: "Bạn có chắc chắn muốn xóa bình luận này? Hành động này không thể hoàn tác.",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#ef4444', // Màu đỏ (Tailwind: red-500)
      cancelButtonColor: '#9ca3af',  // Màu xám (Tailwind: gray-400)
      confirmButtonText: 'Xóa ngay',
      cancelButtonText: 'Hủy',
      customClass: {
        popup: 'rounded-3xl shadow-2xl border border-gray-100' // Bo góc chuẩn form KND Food
      }
    }).then(async (result) => {
      // Nếu người dùng bấm Xóa ngay
      if (result.isConfirmed) {
        try {
          const token = localStorage.getItem("token");
          const response = await fetch(`${API_BASE_URL}/comments/${commentId}`, {
            method: "DELETE",
            headers: { "Authorization": `Bearer ${token}` },
          });

          if (response.ok) {
            // Xóa cmt khỏi danh sách
            setComments((prev) => prev.filter((c) => c.id !== commentId));
            toast.success("✅ Đã xóa bình luận!", toastConfig);
          } else {
            const data = await response.json();
            toast.error(`❌ ${data.message || "Không thể xóa!"}`, toastConfig);
          }
        } catch (error) {
          console.error("Lỗi xóa bình luận:", error);
          toast.error("❌ Lỗi kết nối khi xóa!", toastConfig);
        }
      }
    });
  };

// ==========================================
// API YÊU THÍCH - LƯU CÔNG THỨC
// ==========================================

// 1. Kiểm tra xem User đã lưu món này chưa
app.get("/api/favorites/check/:recipeId", authenticateToken, async (req, res) => {
    try {
        const recipeId = req.params.recipeId;
        const userId = req.user.userId;

        await poolConnect;
        const checkReq = new mssql.Request(pool);
        const result = await checkReq
            .input("UserID", mssql.Int, userId)
            .input("RecipeID", mssql.Int, recipeId)
            .query("SELECT 1 FROM Favorites WHERE UserID = @UserID AND RecipeID = @RecipeID");

        res.status(200).json({ isSaved: result.recordset.length > 0 });
    } catch (err) {
        console.error("Lỗi kiểm tra lưu công thức:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// 2. button: Toggle (Lưu / Hủy lưu)
app.post("/api/favorites/toggle", authenticateToken, async (req, res) => {
    try {
        const { RecipeID } = req.body;
        const UserID = req.user.userId;

        await poolConnect;
        const request = new mssql.Request(pool);
        
        const checkResult = await request
            .input("UserID", mssql.Int, UserID)
            .input("RecipeID", mssql.Int, RecipeID)
            .query("SELECT 1 FROM Favorites WHERE UserID = @UserID AND RecipeID = @RecipeID");

        if (checkResult.recordset.length > 0) {
            // Nếu đã có -> bỏ lưu (Xóa khỏi Favorites)
            await request.query("DELETE FROM Favorites WHERE UserID = @UserID AND RecipeID = @RecipeID");
            return res.status(200).json({ message: "Đã bỏ lưu công thức", isSaved: false });
        } else {
            // Nếu chưa có -> lưu (Thêm vào Favorites)
            await request.query("INSERT INTO Favorites (UserID, RecipeID, CreatedAt) VALUES (@UserID, @RecipeID, GETDATE())");
            return res.status(200).json({ message: "Đã lưu vào bộ sưu tập", isSaved: true });
        }
    } catch (err) {
        console.error("Lỗi toggle lưu công thức:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// ==========================================
// API: LẤY DANH SÁCH MÓN ĂN ĐÃ LƯU (YÊU THÍCH) CỦA USER
// ==========================================
app.get("/api/favorites/my-favorites", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        await poolConnect;
        const request = new mssql.Request(pool);
        const result = await request
            .input("UserID", mssql.Int, userId)
            .query(`
                SELECT 
                    r.RecipeID, r.Title, r.ImageURL, r.Difficulty,
                    r.PrepTime, r.CookTime, r.CategoryID, u.FullName,
                    ISNULL(c.AverageRating, 0) AS AverageRating,
                    ISNULL(c.ReviewCount, 0) AS ReviewCount
                FROM Favorites f
                JOIN Recipes r ON f.RecipeID = r.RecipeID
                LEFT JOIN Users u ON r.UserID = u.UserID
                LEFT JOIN (
                    SELECT 
                        RecipeID, 
                        AVG(CAST(Rating AS FLOAT)) AS AverageRating, 
                        COUNT(CommentID) AS ReviewCount
                    FROM Comments
                    GROUP BY RecipeID
                ) c ON r.RecipeID = c.RecipeID
                WHERE f.UserID = @UserID
                ORDER BY f.CreatedAt DESC
            `);

        res.status(200).json(result.recordset);
    } catch (err) {
        console.error("Lỗi lấy danh sách yêu thích:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// ==========================================
// API: GỢI Ý MÓN ĂN (GỌI SANG PYTHON AI SERVICE)
// ==========================================
app.get("/api/recipes/recommend/:id", async (req, res) => {
    try {
        const targetRecipeId = parseInt(req.params.id);

        await poolConnect;
        const request = new mssql.Request(pool);

        // 1. Lấy tất cả món ăn ĐÃ DUYỆT kèm danh mục
        const recipesResult = await request.query(`
            SELECT r.RecipeID, r.Title, c.CategoryName
            FROM Recipes r
            LEFT JOIN Categories c ON r.CategoryID = c.CategoryID
            WHERE r.Status = 'Approved' OR r.Status = 'Published' OR r.Status IS NULL
        `);
        let allRecipes = recipesResult.recordset;

        // 2. Lấy tất cả nguyên liệu để ghép vào
        const ingResult = await request.query(`
            SELECT RecipeID, IngredientName
            FROM Ingredients
        `);
        const allIngs = ingResult.recordset;

        // 3. Nhào nặn dữ liệu để gửi cho Python
        allRecipes = allRecipes.map(recipe => {
            const ings = allIngs.filter(i => i.RecipeID === recipe.RecipeID).map(i => i.IngredientName).join(" ");
            return {
                RecipeID: recipe.RecipeID,
                Title: recipe.Title || "",
                CategoryName: recipe.CategoryName || "",
                IngredientsText: ings
            };
        });

        // 4. Gọi sang Python FastAPI (chạy ở cổng 8000)
        const pythonResponse = await fetch("http://localhost:8000/api/recommend", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target_recipe_id: targetRecipeId,
                all_recipes: allRecipes
            })
        });
        
        const pythonData = await pythonResponse.json();
        const recommendedIds = pythonData.recommended_ids;

        if (!recommendedIds || recommendedIds.length === 0) {
            return res.status(200).json([]); // Không có gợi ý
        }

        // 5. Lấy thông tin chi tiết của các món được AI gợi ý để hiển thị ra UI
        const idList = recommendedIds.join(",");
        const finalResult = await request.query(`
            SELECT 
                r.RecipeID, r.Title, r.ImageURL, r.Difficulty,
                r.PrepTime, r.CookTime, r.CategoryID, u.FullName,
                ISNULL(c.AverageRating, 0) AS AverageRating,
                ISNULL(c.ReviewCount, 0) AS ReviewCount
            FROM Recipes r
            LEFT JOIN Users u ON r.UserID = u.UserID
            LEFT JOIN (
                SELECT RecipeID, AVG(CAST(Rating AS FLOAT)) AS AverageRating, COUNT(CommentID) AS ReviewCount
                FROM Comments GROUP BY RecipeID
            ) c ON r.RecipeID = c.RecipeID
            WHERE r.RecipeID IN (${idList})
        `);

        // Sắp xếp lại đúng thứ tự độ tương đồng (Giống nhất lên đầu) mà Python đã trả về
        const sortedFinalResult = recommendedIds.map(id => finalResult.recordset.find(r => r.RecipeID === id)).filter(Boolean);

        res.status(200).json(sortedFinalResult);

    } catch (err) {
        console.error("Lỗi Hệ thống AI Recommend:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// Khởi động Server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại: http://localhost:${PORT}`);
});