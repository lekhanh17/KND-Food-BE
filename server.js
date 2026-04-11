const express = require("express");
const mssql = require("mssql");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const sql = require("mssql");
const jwt = require("jsonwebtoken"); // <-- THÊM MỚI: Thư viện tạo Token

const app = express();
app.use(express.json());
app.use(cors());

// Thêm avt
const multer = require("multer");
const path = require("path");

// Cấu hình cho phép Frontend truy cập vào thư mục uploads để lấy ảnh hiện lên web
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
// BỘ MIDDLEWARE PHÂN QUYỀN (THÊM MỚI ĐỂ KHÔNG BỊ LỖI)
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

// 2. NHÂN VIÊN VÀ ADMIN
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

// THÊM BẢO VỆ: Chỉ Admin/Staff mới xem được danh sách User
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

    // THÊM MỚI: TẠO TOKEN ĐỂ KIỂM TRA QUYỀN
    const token = jwt.sign(
      { userId: user.UserID, role: user.Role },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Đăng nhập thành công! BỔ SUNG AVATAR, USERNAME, BIO để Frontend lưu LocalStorage
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

// API XÓA NGƯỜI DÙNG (THÊM BẢO VỆ: Chỉ Admin)
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
// API: ADMIN CẬP NHẬT VAI TRÒ (THÊM BẢO VỆ: Chỉ Admin)
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
    // Nhận thêm Username và Bio từ gói dữ liệu req.body
    const { UserID, FullName, Email, Username, Bio } = req.body;
    await poolConnect;

    await pool
      .request()
      .input("UserID", mssql.Int, UserID)
      .input("FullName", mssql.NVarChar, FullName)
      .input("Email", mssql.VarChar, Email)
      .input("Username", mssql.VarChar, Username) // VarChar vì username không dấu
      .input("Bio", mssql.NVarChar, Bio) // NVarChar vì bio có thể gõ tiếng Việt
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

    // 1. KIỂM TRA EMAIL TRONG DATABASE
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

    // 3. Cập nhật vào DB (ĐÃ SỬA THÀNH PasswordHash)
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
// API TẠO CÔNG THỨC MỚI (THÊM STATUS = PENDING VÀO LÚC TẠO)
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

    // Xử lý Ảnh bìa
    const mainImageFile = req.files.find((f) => f.fieldname === "mainImage");
    const mainImageUrl = mainImageFile
      ? `http://localhost:5000/uploads/${mainImageFile.filename}`
      : null;

    // --- XỬ LÝ VIDEO ---
    let finalVideoUrl = null;
    const mainVideoFile = req.files.find((f) => f.fieldname === "mainVideo");

    if (mainVideoFile) {
      finalVideoUrl = `http://localhost:5000/uploads/${mainVideoFile.filename}`;
    } else if (VideoUrl && VideoUrl.trim() !== "") {
      finalVideoUrl = VideoUrl.trim();
    }

    // Thêm vào bảng Recipes (ĐÃ BỔ SUNG CỘT STATUS)
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

    // Thêm vào bảng Ingredients
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

    // Thêm vào bảng RecipeSteps
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
// API LẤY DANH SÁCH TẤT CẢ MÓN ĂN (SỬA LẠI: CHỈ LẤY MÓN ĐÃ DUYỆT)
// ==========================================
app.get("/api/recipes", async (req, res) => {
  try {
    await poolConnect;
    const request = new mssql.Request(pool);

    const result = await request.query(`
            SELECT 
                r.RecipeID, r.Title, r.ImageURL, r.Difficulty, 
                r.PrepTime, r.CookTime, r.CategoryID, u.FullName
            FROM Recipes r
            LEFT JOIN Users u ON r.UserID = u.UserID
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
            SELECT RecipeID, Title, ImageURL, Difficulty, PrepTime, CookTime 
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
// API: TÌM KIẾM NHANH (MÓN ĂN & NGƯỜI DÙNG)
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
// API: LẤY THÔNG TIN HỒ SƠ QUA USERNAME
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
// NHÓM API MỚI: DÀNH CHO NHÂN VIÊN DUYỆT BÀI
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

// 2. Duyệt bài (Cho phép món ăn hiển thị lên trang chủ)
app.put("/api/admin/approve-recipe/:id", authenticateToken, isAdminOrStaff, async (req, res) => {
    try {
        const { id } = req.params;
        await poolConnect;
        const result = await pool.request()
            .input("RecipeID", mssql.Int, id)
            .query("UPDATE Recipes SET Status = 'Approved' WHERE RecipeID = @RecipeID");

        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ message: "Không tìm thấy món ăn!" });
        }
        res.json({ message: "Đã duyệt món ăn thành công!" });
    } catch (err) {
        console.error("Lỗi duyệt bài:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// 3. Từ chối và xóa bài viết vi phạm
app.delete("/api/admin/reject-recipe/:id", authenticateToken, isAdminOrStaff, async (req, res) => {
    try {
        const { id } = req.params;
        await poolConnect;
        const result = await pool.request()
            .input("RecipeID", mssql.Int, id)
            .query("DELETE FROM Recipes WHERE RecipeID = @RecipeID");
        
        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ message: "Không tìm thấy món ăn!" });
        }
        res.json({ message: "Đã từ chối và xóa bài đăng!" });
    } catch (err) {
        console.error("Lỗi từ chối bài:", err);
        res.status(500).json({ message: "Lỗi Server!" });
    }
});

// Khởi động Server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại: http://localhost:${PORT}`);
});