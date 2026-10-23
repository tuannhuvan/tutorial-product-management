# TÀI LIỆU ĐẶC TẢ YÊU CẦU NGHIỆP VỤ (SRS - SYSTEM REQUIREMENTS SPECIFICATION)
## HỆ THỐNG CỔNG TÀI KHOẢN HỌC VIÊN FPT APTECH (STUDENT ACCOUNT PORTAL)

---

### 1. TỔNG QUAN DỰ ÁN & MỤC TIÊU
#### 1.1 Tổng quan
Dự án **Cổng tài khoản học viên FPT Aptech** là hệ thống quản lý xác thực và phân quyền trung tâm dành cho học viên (STUDENT), giảng viên (LECTURER) và quản trị viên (ADMIN). Hệ thống đóng vai trò Cổng xác thực dùng chung (Identity Provider - IdP), đảm bảo tính an toàn, bảo mật cao cấp theo chuẩn công nghiệp cho toàn bộ hệ sinh thái ứng dụng FPT Aptech.

#### 1.2 Mục tiêu nghiệp vụ
- Tự động hóa luồng đăng ký học viên, xác minh email và thiết lập mật khẩu an toàn.
- Cung cấp cơ chế xác thực đa yếu tố (2FA - TOTP RFC 6238) bắt buộc cho Giảng viên và Quản trị viên.
- Phòng chống các cuộc tấn công dò mật khẩu (Brute-force/Credential Stuffing) bằng cơ chế khóa tài khoản tự động linh hoạt.
- Quản lý phiên đăng nhập tập trung (Session Management) với giới hạn số phiên đồng thời và tính năng đăng xuất từ xa.
- Đảm bảo tính minh bạch thông qua Nhật ký kiểm toán (Audit Log) theo dõi toàn bộ biến động tài khoản.

---

### 2. PHÂN CẤP VAI TRÒ VÀ QUYỀN HẠN (RBAC)

Hệ thống định nghĩa 3 vai trò chính với các đặc quyền sau:

| Vai trò | Cơ chế tạo tài khoản | Quyền hạn & Chức năng được phép | Bắt buộc 2FA (TOTP) |
| :--- | :--- | :--- | :--- |
| **STUDENT** (Học viên) | Tự đăng ký công khai qua Email | - Tự đăng ký tài khoản học viên.<br>- Xem & cập nhật thông tin hồ sơ cá nhân.<br>- Đổi mật khẩu cá nhân.<br>- Quản lý các phiên đăng nhập của chính mình (xem thiết bị, đăng xuất từ xa). | Tùy chọn (Optional) |
| **LECTURER** (Giảng viên) | ADMIN khởi tạo (Gửi email mời) | - Các quyền tương tự STUDENT.<br>- Xem danh sách học viên (chế độ chỉ đọc - Read-only). | **BẮT BUỘC** |
| **ADMIN** (Quản trị viên) | Khởi tạo ban đầu qua Migration / ADMIN khác | - Quản lý toàn bộ tài khoản: Tìm kiếm, lọc, xem chi tiết.<br>- Khóa / Mở khóa tài khoản thủ công.<br>- Vô hiệu hóa (Disable) tài khoản.<br>- Gán / Thay đổi vai trò (Role).<br>- Buộc đăng xuất (Terminate sessions).<br>- Xem & lọc Nhật ký kiểm toán (Audit Logs). | **BẮT BUỘC** |

---

### 3. VÒNG ĐỜI VÀ TRẠNG THÁI TÀI KHOẢN (ACCOUNT LIFECYCLE)

Tài khoản trong hệ thống chuyển dịch qua **5 trạng thái chuẩn**:

```
                  ┌────────────────────────┐
                  │ PENDING (Chờ xác minh) │
                  └───────────┬────────────┘
                              │ (Xác minh email trong 24h)
                              ▼
┌──────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
│  INVITED (Mời)   ├────►│   ACTIVE (Hoạt động)   ├────►│ LOCKED (Khóa tạm 15m)  │
└──────────────────┘     └───────────┬────────────┘     └────────────────────────┘
  (Đặt mật khẩu)                      │ (ADMIN vô hiệu hóa)
                                      ▼
                         ┌────────────────────────┐
                         │ DISABLED (Vô hiệu hóa) │
                         └────────────────────────┘
```

#### Chi tiết các trạng thái:
1. **PENDING (Chờ xác minh Email)**: Áp dụng khi Học viên tự đăng ký. Chưa thể đăng nhập vào hệ thống. Cần nhấp link xác minh trong email (hiệu lực 24 giờ).
2. **INVITED (Chờ đặt mật khẩu)**: Áp dụng khi ADMIN khởi tạo tài khoản LECTURER/ADMIN. Hệ thống gửi email chứa liên kết thiết lập mật khẩu lần đầu.
3. **ACTIVE (Hoạt động)**: Trạng thái duy nhất cho phép người dùng đăng nhập thành công và truy cập hệ thống.
4. **LOCKED (Khóa tạm thời)**: Tự động kích hoạt khi nhập sai mật khẩu 5 lần liên tiếp trong vòng 15 phút. Khóa trong 15 phút (hoặc cho đến khi ADMIN mở khóa thủ công).
5. **DISABLED (Bị vô hiệu hóa)**: Do ADMIN thực hiện. Khi chuyển sang DISABLED, hệ thống **hủy ngay lập tức tất cả các phiên làm việc (sessions) và Remember-me token** đang hoạt động của tài khoản.

*Lưu ý bảo mật*: Mọi nỗ lực đăng nhập vào tài khoản không ở trạng thái ACTIVE đều trả về **cùng một thông báo lỗi chung** ("Tài khoản hoặc mật khẩu không chính xác hoặc chưa được kích hoạt") để tránh lộ trạng thái nội bộ.

---

### 4. ĐẶC TẢ YÊU CẦU CHỨC NĂNG CHI TIẾT (F1 - F11)

#### F1: Đăng ký bằng Email
- **Actor**: Khách (Chưa đăng nhập).
- **Mô tả**: Cho phép học viên tự đăng ký tài khoản bằng email.
- **Tiêu chí nghiệm thu (Acceptance Criteria)**:
  - Tiếp nhận Username, Email, Mật khẩu, Nhập lại mật khẩu.
  - Tạo tài khoản ở trạng thái `PENDING`.
  - Hệ thống tự động tạo Token xác minh (băm SHA-256 trong CSDL) và gửi Email xác minh chứa liên kết chứa Token.
  - Tài khoản `PENDING` chưa được phép đăng nhập.

#### F2: Xác minh Email
- **Actor**: Học viên (qua liên kết Email).
- **Mô tả**: Người dùng kích hoạt tài khoản qua Token trong Email.
- **Tiêu chí nghiệm thu**:
  - Token dùng 1 lần, hết hạn sau **24 giờ**.
  - Token lưu trữ dưới dạng băm **SHA-256** trong CSDL (không lưu dạng rõ).
  - Cho phép gửi lại email xác minh tối đa **3 lần / giờ / tài khoản**.
  - Sau khi xác minh thành công, trạng thái chuyển từ `PENDING` -> `ACTIVE`.

#### F3: Quên mật khẩu & Khôi phục
- **Actor**: Người dùng đã có tài khoản.
- **Mô tả**: Yêu cầu khôi phục mật khẩu qua Email.
- **Tiêu chí nghiệm thu**:
  - Token khôi phục hết hạn sau **30 phút**, chỉ sử dụng 1 lần.
  - **Phản hồi đồng nhất** (Uniform Response): Hệ thống hiển thị thông báo "Nếu email tồn tại trong hệ thống, liên kết khôi phục đã được gửi" bất kể email có tồn tại hay không (chống Email Enumeration attack).
  - Khi đổi mật khẩu thành công: Tất cả các phiên làm việc cũ (sessions) và Remember-me tokens của người dùng **phải bị hủy lập tức**.

#### F4: Chính sách Mật khẩu (Password Policy)
- **Mô tả**: Quy chuẩn độ mạnh mật khẩu khi đăng ký / đổi mật khẩu.
- **Tiêu chí nghiệm thu**:
  - Độ dài tối thiểu **12 ký tự**.
  - Không được chứa `username` hoặc phần tên của `email`.
  - Không nằm trong danh sách **10.000 mật khẩu phổ biến nhất** (Common Password List).
  - Không trùng lặp với **5 mật khẩu gần nhất** trong lịch sử tài khoản.

#### F5: Khóa tài khoản tạm thời (Brute-force Protection)
- **Mô tả**: Ngăn chặn tấn công dò quét mật khẩu.
- **Tiêu chí nghiệm thu**:
  - Nhập sai mật khẩu **5 lần liên tiếp trong vòng 15 phút** -> Tự động chuyển tài khoản sang trạng thái `LOCKED` trong **15 phút**.
  - Hết 15 phút hoặc khi ADMIN thực hiện mở khóa -> Chuyển về `ACTIVE`.
  - Thông báo lỗi đăng nhập không tiết lộ tài khoản có bị khóa hay tồn tại hay không.

#### F6: Xác thực 2 bước (TOTP - RFC 6238)
- **Mô tả**: Xác thực 2 yếu tố qua ứng dụng Authenticator (Google/Microsoft Authenticator).
- **Tiêu chí nghiệm thu**:
  - Thiết lập bằng QR Code / Secret Key.
  - Sinh **10 mã khôi phục (Recovery Codes)** dùng 1 lần khi kích hoạt TOTP.
  - Bí mật TOTP (TOTP Secret) bắt buộc **mã hóa AES-GCM** khi lưu trong CSDL.
  - Bắt buộc với `LECTURER` và `ADMIN`: Sau khi đăng nhập bằng mật khẩu, nếu chưa bật TOTP, người dùng bị chuyển hướng bắt buộc vào trang thiết lập 2FA trước khi truy cập tính năng khác.

#### F7: Ghi nhớ đăng nhập (Remember-me)
- **Mô tả**: Duy trì trạng thái đăng nhập qua Token an toàn.
- **Tiêu chí nghiệm thu**:
  - Lưu Persistent Token trong CSDL (`persistent_logins`).
  - Hiệu lực tối đa **14 ngày**.
  - Tự động thu hồi/xóa token Remember-me khi người dùng thực hiện đổi mật khẩu hoặc đăng xuất.

#### F8: Quản lý phiên đăng nhập (Session Management)
- **Mô tả**: Kiểm soát phiên làm việc đồng thời của tài khoản.
- **Tiêu chí nghiệm thu**:
  - Tối đa **2 phiên đăng nhập đồng thời** cho mỗi tài khoản (sử dụng Spring Session JDBC).
  - Trang "Thiết bị đăng nhập" hiển thị chi tiết: Thời điểm đăng nhập, Địa chỉ IP, Trình duyệt/Thiết bị (User-Agent), Đánh dấu phiên hiện tại.
  - Cho phép người dùng bấm "Đăng xuất" từ xa từng phiên cụ thể.

#### F9: Đổi mật khẩu khi đang đăng nhập
- **Mô tả**: Người dùng chủ động đổi mật khẩu trong trang cá nhân.
- **Tiêu chí nghiệm thu**:
  - Bắt buộc xác nhận mật khẩu hiện tại (Current Password).
  - Sau khi đổi thành công: **Hủy tất cả các phiên đăng nhập khác**, giữ lại duy nhất phiên hiện tại.

#### F10: Quản trị tài khoản (Admin Portal)
- **Mô tả**: Bộ công cụ dành cho Quản trị viên điều hành người dùng.
- **Tiêu chí nghiệm thu**:
  - Bảng danh sách phân trang (Pagination), tìm kiếm theo Email/Username, lọc theo Role và Status.
  - Tính năng: Khóa/Mở khóa, Vô hiệu hóa (Disable), Gán vai trò, Buộc đăng xuất (Kill session).
  - **Ràng buộc hệ thống bắt buộc**: Hệ thống luôn phải duy trì **ít nhất 01 tài khoản ADMIN ở trạng thái ACTIVE**. ADMIN không thể tự gỡ quyền ADMIN của chính mình.

#### F11: Nhật ký kiểm toán (Audit Logs)
- **Mô tả**: Ghi vết mọi thao tác nhạy cảm liên quan đến an ninh tài khoản.
- **Tiêu chí nghiệm thu**:
  - Tự động ghi nhận các sự kiện: Đăng nhập thành công/thất bại, Đăng xuất, Khóa/Mở khóa, Đổi mật khẩu, Đổi vai trò, Bật/Tắt 2FA, Vô hiệu hóa tài khoản.
  - Nội dung bản ghi: Timestamp, Account ID/Username, Địa chỉ IP, User-Agent, Loại sự kiện (Event Type), Chi tiết kết quả.
  - ADMIN có giao diện xem và lọc Audit Log theo thời gian, hành động, IP.

---

### 5. YÊU CẦU PHI CHỨC NĂNG & RÀNG BUỘC KỸ THUẬT

#### 5.1 Bảo mật & An toàn thông tin
- **Mật khẩu**: Băm bằng `DelegatingPasswordEncoder` (mặc định BCrypt `{bcrypt}`). Hỗ trợ tự động nâng cấp băm (Re-hash) khi đăng nhập thành công nếu thuật toán cũ yếu hơn.
- **Mã hóa dữ liệu nhạy cảm**: Khóa bí mật TOTP được mã hóa AES-GCM với Key lấy từ biến môi trường.
- **Chống tấn công Web**:
  - CSRF: Bật mặc định trên tất cả Form POST.
  - Cookie: `HttpOnly=true`, `SameSite=Lax`, `Secure=true` (trên Production).
  - Header bảo mật: Bật HSTS và Content Security Policy (CSP) chặt chẽ.
- **Giới hạn tần suất (Rate Limiting)**:
  - Theo IP: Tối đa 10 lượt đăng ký/giờ, 20 lượt gửi email quên mật khẩu/giờ.
- **Chống tấn công dò thời gian (Timing Attack)**:
  - Thời gian xử lý `POST /login` khi username không tồn tại và khi sai mật khẩu **chênh lệch không quá 50ms**.
- **Không ghi Log nhạy cảm**: Tuyệt đối không ghi Mật khẩu, Token rõ, Mã TOTP vào File Log.

#### 5.2 Ràng buộc Công nghệ (Tech Stack)
- **Java**: JDK 25 (LTS).
- **Framework**: Spring Boot 4.1.x, Spring Security 7.1.x (Lambda DSL, `SecurityFilterChain`).
- **Persistence**: Spring Data JPA, Spring Session JDBC (cho F8).
- **Database**: MySQL 8.4 LTS, Quản lý Migration bằng **Flyway**.
- **Dev & Test Infrastructure**: Docker Compose (MySQL 8.4, Mailpit cho SMTP dev), H2 Database (In-Memory cho Integration Tests).
