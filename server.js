const express = require("express");
const mssql = require("mssql");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const sql = require("mssql");

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

app.get("/api/users", async (req, res) => {
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

    // Đăng nhập thành công! BỔ SUNG AVATAR, USERNAME, BIO để Frontend lưu LocalStorage
    res.json({
      message: `Chào mừng ${user.FullName} trở lại!`,
      user: {
        UserID: user.UserID,
        FullName: user.FullName,
        Email: user.Email,
        Role: user.Role,
        Avatar: user.Avatar, // <-- THÊM MỚI
        Username: user.Username, // <-- THÊM MỚI
        Bio: user.Bio, // <-- THÊM MỚI
      },
    });
  } catch (err) {
    console.error("Lỗi đăng nhập: ", err);
    res.status(500).json({ message: "Lỗi Server" });
  }
});

// API XÓA NGƯỜI DÙNG (Dành cho Admin)
app.delete("/api/users/:id", async (req, res) => {
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
// API: ADMIN CẬP NHẬT VAI TRÒ 
// ==========================================
app.put("/api/admin/update-role", async (req, res) => {
  try {
    const { userId, newRole } = req.body;
    console.log("Đang đổi quyền cho ID:", userId, "Thành:", newRole); // Dòng này để kiểm tra dữ liệu gửi lên

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
    // KHI BỊ LỖI, BẠN NHÌN VÀO TERMINAL VS CODE SẼ THẤY DÒNG DƯỚI ĐÂY:
    console.error("LỖI SQL CHI TIẾT:", error.message); 
    res.status(500).json({ message: "Lỗi máy chủ không thể cập nhật vai trò." });
  }
});

// ==========================================
// API CẬP NHẬT THÔNG TIN CÁ NHÂN (ĐÃ NÂNG CẤP)
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
    // Nhớ đảm bảo có dòng: const crypto = require('crypto'); ở đầu file nhé
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
// API TẠO CÔNG THỨC MỚI
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
      // Nếu có file video tải lên từ local
      finalVideoUrl = `http://localhost:5000/uploads/${mainVideoFile.filename}`;
    } else if (VideoUrl && VideoUrl.trim() !== "") {
      // Nếu không có file tải lên, nhưng có link video
      finalVideoUrl = VideoUrl.trim();
    }

    // Thêm vào bảng Recipes
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
                INSERT INTO Recipes (UserID, CategoryID, Title, Description, ImageURL, VideoURL, PrepTime, CookTime, Servings, Difficulty)
                OUTPUT INSERTED.RecipeID
                VALUES (@UserID, @CategoryID, @Title, @Description, @ImageURL, @VideoURL, @PrepTime, @CookTime, @Servings, @Difficulty)
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
    res.status(201).json({ message: "Đăng công thức thành công!" });
  } catch (err) {
    // 1. IN RA LỖI GỐC THỰC SỰ TRƯỚC
    console.error("LỖI GỐC TỪ SQL:", err.message);

    // 2. Ép lỗi cho hàm rollback để nó không bị văng app
    try {
      await transaction.rollback();
    } catch (rollbackErr) {
      // Bỏ qua lỗi báo "Transaction đã bị abort"
    }

    res.status(500).json({ message: "Lỗi Server: " + err.message });
  }
});

// ==========================================
// API LẤY DANH SÁCH TẤT CẢ MÓN ĂN (CHO TRANG CHỦ)
// ==========================================
app.get("/api/recipes", async (req, res) => {
  try {
    await poolConnect;
    const request = new mssql.Request(pool);

    // Lấy thông tin cơ bản của món ăn kèm tên tác giả
    const result = await request.query(`
            SELECT 
                r.RecipeID, r.Title, r.ImageURL, r.Difficulty, 
                r.PrepTime, r.CookTime, r.CategoryID, u.FullName
            FROM Recipes r
            LEFT JOIN Users u ON r.UserID = u.UserID
            ORDER BY r.RecipeID DESC -- Hoặc ORDER BY r.CreatedAt DESC nếu bạn có cột CreatedAt
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

    // Lấy dữ liệu từ bảng Recipes, sắp xếp món mới nhất lên đầu (ORDER BY RecipeID DESC)
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

    // 1. Lấy thông tin chung món ăn (Kèm theo thông tin Tác giả)
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

    // 2. Lấy danh sách Nguyên liệu
    const ingReq = pool.request();
    ingReq.input("RecipeID", mssql.Int, id);
    const ingResult = await ingReq.query(
      `SELECT * FROM Ingredients WHERE RecipeID = @RecipeID`,
    );
    recipe.ingredients = ingResult.recordset;

    // 3. Lấy Các bước thực hiện
    const stepReq = pool.request();
    stepReq.input("RecipeID", mssql.Int, id);
    const stepResult = await stepReq.query(
      `SELECT * FROM RecipeSteps WHERE RecipeID = @RecipeID ORDER BY StepNumber ASC`,
    );
    recipe.steps = stepResult.recordset;

    // Trả về toàn bộ cục dữ liệu
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
      UserID,
      Title,
      Description,
      PrepTime,
      CookTime,
      Servings,
      Difficulty,
      CategoryID,
      ingredients,
      steps,
    } = req.body;

    await poolConnect;
    const transaction = new mssql.Transaction(pool);
    await transaction.begin();

    try {
      // 1. Kiểm tra xem user này có phải chủ món ăn không
      const checkReq = new mssql.Request(transaction);
      checkReq.input("RecipeID", mssql.Int, id);
      const checkRes = await checkReq.query(
        `SELECT UserID FROM Recipes WHERE RecipeID = @RecipeID`,
      );

      if (checkRes.recordset.length === 0)
        throw new Error("Không tìm thấy món ăn");
      if (checkRes.recordset[0].UserID !== UserID)
        throw new Error("Bạn không có quyền sửa món ăn này");

      // 2. Cập nhật bảng Recipes (Đã ép kiểu Số an toàn tuyệt đối)
      const updateReq = new mssql.Request(transaction);

      // Ép id thành số
      updateReq.input("RecipeID", mssql.Int, parseInt(id) || 0);
      updateReq.input("Title", mssql.NVarChar, String(Title || ""));
      updateReq.input("Description", mssql.NVarChar, String(Description || ""));

      // Dùng parseInt để đảm bảo nếu user để trống "" thì nó sẽ tự biến thành số 0
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

      // 3. Cập nhật Nguyên liệu (Xóa cũ, Thêm mới)
      const delIngReq = new mssql.Request(transaction);
      delIngReq.input("RecipeID", mssql.Int, id);
      await delIngReq.query(
        `DELETE FROM Ingredients WHERE RecipeID = @RecipeID`,
      );

      if (ingredients && ingredients.length > 0) {
        for (const ing of ingredients) {
          const addIngReq = new mssql.Request(transaction);
          addIngReq.input("RecipeID", mssql.Int, id);

          // SỬA Ở ĐÂY: Dùng String(...) và || '' để đảm bảo nó luôn là Chuỗi hợp lệ, không bao giờ bị lỗi Invalid string
          addIngReq.input(
            "IngredientName",
            mssql.NVarChar,
            String(ing.IngredientName || ""),
          );
          addIngReq.input(
            "Quantity",
            mssql.NVarChar,
            String(ing.Quantity || ""),
          );
          addIngReq.input("Unit", mssql.NVarChar, String(ing.Unit || ""));

          await addIngReq.query(`
                        INSERT INTO Ingredients (RecipeID, IngredientName, Quantity, Unit) 
                        VALUES (@RecipeID, @IngredientName, @Quantity, @Unit)
                    `);
        }
      }

      // 4. Cập nhật Các bước thực hiện (Xóa cũ, Thêm mới)
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
          addStepReq.input(
            "Instruction",
            mssql.NVarChar,
            String(step.Instruction || ""),
          );

          // SỬA Ở ĐÂY: Thêm input cho ImageURL để không bị mất ảnh cũ
          if (step.ImageURL) {
            addStepReq.input("ImageURL", mssql.NVarChar, String(step.ImageURL));
          } else {
            addStepReq.input("ImageURL", mssql.NVarChar, null);
          }

          // Nhớ thêm cột ImageURL vào câu lệnh INSERT
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

    // Tìm 5 công thức (Sửa tên cột Title, ImageURL cho đúng DB của bạn nhé)
    const recipesResult = await pool.request()
      .input("Term", sql.NVarChar, sqlSearchTerm)
      .query(`
        SELECT TOP 5 RecipeID, Title, ImageURL 
        FROM Recipes 
        WHERE Title LIKE @Term
      `);

    // Tìm 3 người dùng
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

// Khởi động Server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server đang chạy tại: http://localhost:${PORT}`);
});
