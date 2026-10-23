# CỔNG TÀI KHOẢN HỌC VIÊN FPT APTECH (STUDENT ACCOUNT PORTAL)
> Hệ thống Xác thực tập trung và Quản lý Phân quyền bảo mật cao cấp (Identity Provider - IdP) đạt chuẩn công nghiệp NIST SP 800-63B và OWASP Top 10.

---

## 1. KHỞI CHẠY ỨNG DỤNG BẰNG 1 LỆNH DUY NHẤT

### Yêu cầu tiên quyết (Prerequisites)
- **Java**: JDK 25 LTS (hoặc JDK 21+).
- **Cơ sở dữ liệu**: MySQL 8.0/8.4 đang chạy tại `localhost:3306` (Username: `root`, Password: `root`, Database: `student_account_portal` tự động sinh nếu chưa có).
  *(Tùy chọn: khởi chạy nhanh hạ tầng DB và Mailpit bằng lệnh `docker compose up -d` trong thư mục `demoStudentAccountPortal`).*

### Lệnh khởi chạy duy nhất:
Di chuyển vào thư mục dự án và thực thi:
- **Trên Linux / macOS**:
  ```bash
  cd demoStudentAccountPortal && ./mvnw spring-boot:run
  ```
- **Trên Windows (PowerShell / CMD)**:
  ```cmd
  cd demoStudentAccountPortal ; .\mvnw.cmd spring-boot:run
  ```

Hệ thống sẽ tự động tải các dependencies, khởi tạo bảng CSDL và seed tài khoản mặc định, sau đó khởi chạy Web server tại:
👉 **URL Hệ thống**: [http://localhost:8080](http://localhost:8080)

---

## 2. TÀI KHOẢN TRUY CẬP ĐỊNH SẴN (PRE-SEEDED ACCOUNTS)

Hệ thống đã tự động tạo sẵn 2 tài khoản quản trị và người dùng mẫu để kiểm thử ngay lập tức:

| Vai trò (Role) | Username | Password | Trạng thái | Yêu cầu 2FA (TOTP) | Chức năng chính |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ADMIN & LECTURER** | `admin` | `Admin@FPT2026!` | `ACTIVE` | **BẮT BUỘC** (Cấu hình ngay khi đăng nhập) | Quản trị tài khoản, phân quyền, khóa/mở khóa, hủy phiên, xem Audit Log |
| **STUDENT (Học viên)** | `hocvien2026` | `MatkhauChuan2026!` | `ACTIVE` | Tùy chọn (Optional) | Hồ sơ cá nhân, đổi mật khẩu, quản lý phiên đăng nhập và thiết bị từ xa |

---

## 3. CHẠY BỘ KIỂM THỬ TỰ ĐỘNG (AUTOMATED TEST SUITE F1–F11)

Toàn bộ 11 chức năng nghiệp vụ (F1–F11) cùng tất cả các kịch bản lỗi bảo mật nghiêm ngặt được tự động kiểm thử độc lập trên In-Memory H2 Database:

### Lệnh chạy kiểm thử:
- **Linux / macOS**:
  ```bash
  cd demoStudentAccountPortal && ./mvnw test
  ```
- **Windows**:
  ```cmd
  cd demoStudentAccountPortal ; .\mvnw.cmd test
  ```

### Ma trận bao phủ kiểm thử (`AuthFlowTest.java` - 15/15 Tests Passed):
- **F1 [Đăng ký]**: Đăng ký học viên bằng email, sinh token SHA-256 kích hoạt, kiểm tra trạng thái `PENDING`.
- **F1 [LỖI]**: Ngăn chặn trùng lặp Username hoặc Email đã tồn tại.
- **F2 [Xác minh Email]**: Kích hoạt tài khoản thành công chuyển từ `PENDING` sang `ACTIVE`.
- **F2 [LỖI - Token Hết Hạn]**: Từ chối kích hoạt khi Token email đã quá hạn 24 giờ.
- **F2 [LỖI - Token Dùng Lại]**: Chống tấn công Replay Attack khi sử dụng lại Token đã kích hoạt một lần.
- **F3 [Quên mật khẩu]**: Gửi liên kết đặt lại mật khẩu với cơ chế phản hồi đồng nhất (Uniform Response) chống rò rỉ danh tính.
- **F3 [LỖI - Token Reset Lỗi]**: Từ chối đặt lại mật khẩu khi Token reset hết hạn (30 phút) hoặc đã qua sử dụng.
- **F4 [Chính sách Mật khẩu]**: Ràng buộc độ dài tối thiểu 12 ký tự, không chứa username/email, cấm mật khẩu nằm trong từ điển phổ biến (OWASP Top 10.000).
- **F4 [LỖI - Lịch sử Mật khẩu]**: Chặn sử dụng lại 5 mật khẩu gần nhất của tài khoản.
- **F5 [LỖI - Khóa Tài Khoản (Brute-Force)]**: Tự động khóa tài khoản (`LOCKED`) sau 5 lần nhập sai liên tiếp trong vòng 15 phút.
- **F6 [2FA TOTP RFC 6238]**: Xác thực 2 bước bằng mã 6 chữ số xoay vòng 30 giây, mã hóa khóa bí mật AES-GCM, sinh 10 mã khôi phục dự phòng.
- **F6 [LỖI - Sai mã TOTP]**: Chặn đăng nhập khi nhập sai mã TOTP 2 bước; chấp nhận mã dự phòng và đánh dấu mã đã dùng.
- **F7 [Remember-Me]**: Ghi nhớ phiên làm việc an toàn 14 ngày lưu trong DB; tự động thu hồi khi đổi mật khẩu hoặc đăng xuất.
- **F8 [Quản lý Phiên]**: Kiểm soát tối đa 2 phiên đăng nhập đồng thời; hỗ trợ hủy phiên và đăng xuất thiết bị từ xa.
- **F9 [Đổi mật khẩu trong phiên]**: Xác thực mật khẩu cũ, cập nhật băm mới và hủy toàn bộ các phiên làm việc từ xa khác.
- **F10 [LỖI - Bảo vệ ADMIN cuối cùng]**: Chặn tuyệt đối hành vi Xóa, Vô hiệu hóa (`DISABLE`) hoặc Gỡ bỏ quyền `ROLE_ADMIN` của Quản trị viên hoạt động duy nhất nhằm chống tê liệt hệ thống.
- **F11 [Audit Logging]**: Tự động ghi vết mọi hành vi an ninh (đăng nhập, khóa tài khoản, đổi mật khẩu, bật 2FA, đổi quyền) kèm IP, thời gian, User-Agent.

---

## 4. TÀI LIỆU MÔ HÌNH MỐI ĐE DỌA (THREAT MODEL DOCUMENT)
*(Chuẩn hóa theo NIST SP 800-63B Digital Identity Guidelines & OWASP Top 10:2021)*

### 4.1. Phạm vi & Mục tiêu bảo vệ
Hệ thống **Student Account Portal** đóng vai trò là Cổng định danh tập trung (Identity Provider). Các tài sản thông tin cốt lõi cần bảo vệ bao gồm:
1. Thông tin xác thực người dùng (Mật khẩu, Khóa bí mật TOTP, Recovery Codes).
2. Phiên làm việc (HTTP Session Cookies, Persistent Remember-Me Tokens).
3. Quyền hạn đặc quyền quản trị (Administrative Privileges & RBAC Integrity).
4. Tính toàn vẹn và bất khả chối bỏ của Nhật ký kiểm toán (Audit Trail).

---

### 4.2. Bảng phân tích các kiểu tấn công và Cơ chế phòng thủ đa lớp (Defense-in-Depth)

| Kiểu tấn công (Threat Vector) | Mối đe dọa & Mục tiêu của kẻ tấn công | Cách hệ thống phòng ngừa & Chặn đứng (Mitigations) | Tiêu chuẩn tuân thủ |
| :--- | :--- | :--- | :--- |
| **1. Vét cạn & Nhồi thông tin (Brute-Force & Credential Stuffing)** | Dò quét mật khẩu người dùng hoặc dùng danh sách rò rỉ (Leaked Dumps) để đăng nhập trái phép. | • **Tự động khóa tài khoản (F5)**: Khóa tạm thời 15 phút sau **5 lần** nhập sai liên tiếp.<br>• **Password Policy (F4)**: Tối thiểu 12 ký tự, cấm mật khẩu nằm trong OWASP Top 10.000 Password List.<br>• **Rate Limiting**: Hạn chế tối đa 10 lượt đăng ký và 20 lượt reset/giờ theo IP. | OWASP A07:2021<br>NIST 800-63B §5.1.1 |
| **2. Tấn công chiếm đoạt & Dùng lại Token (Token Replay & Tampering)** | Đánh cắp Token xác minh Email (F2) hoặc Token đặt lại Mật khẩu (F3) từ đường truyền hoặc nhật ký. | • **Lưu trữ dưới dạng băm SHA-256**: Cơ sở dữ liệu chỉ lưu giá trị hash của Token; kẻ xâm nhập CSDL không thể tái tạo Token gốc.<br>• **Sử dụng 1 lần (One-Time-Use)**: Ngay khi kích hoạt/đổi mật khẩu, Token chuyển sang cờ `used = true`.<br>• **Hạn ngạch thời gian ngắn**: Token Email (24h), Token Reset Mật khẩu (30 phút).<br>• Sinh ngẫu nhiên mã hóa bằng `SecureRandom` 256-bit entropy. | OWASP A01:2021<br>NIST 800-63B §5.1.4 |
| **3. Dò đoán thông tin qua thời gian phản hồi (Timing & User Enumeration Attack)** | Đo thời gian phản hồi của Server để đoán Email/Username có tồn tại hay không trong hệ thống. | • **Phản hồi đồng nhất (Uniform Response)**: Chức năng quên mật khẩu luôn trả về cùng thông điệp thành công dù Email có tồn tại hay không.<br>• **Dummy BCrypt Work Factor**: Khi tài khoản không tồn tại, hệ thống chủ động gọi hàm băm mật khẩu giả định với độ phức tạp tương đương để thời gian phản hồi giữa user đúng và sai lệch không quá 50ms. | OWASP A07:2021<br>CWE-208 |
| **4. Đánh cắp & Vượt rào Xác thực 2 bước (TOTP Bypass & Secret Exfiltration)** | Vượt qua màn hình nhập 2FA, giải mã trộm secret key trong DB hoặc tái sử dụng mã TOTP. | • **Mã hóa đối xứng AES-GCM-256**: Bí mật TOTP được mã hóa bằng AES-GCM với Secret Key độc lập lưu trữ trong biến môi trường hệ thống.<br>• **TotpEnforcementFilter**: Bộ lọc bảo mật chặn tuyệt đối người dùng có vai trò `LECTURER`/`ADMIN` truy cập các endpoint nội bộ nếu chưa kích hoạt 2FA.<br>• **Anti-Replay TOTP**: Mã TOTP xoay vòng mỗi 30 giây theo RFC 6238.<br>• 10 Recovery Codes sinh ra dưới dạng băm và chỉ sử dụng duy nhất một lần. | NIST 800-63B AAL2<br>RFC 6238 / RFC 4226 |
| **5. Chiếm đoạt phiên & Đánh cắp Cookie (Session Hijacking & Remember-Me Theft)** | Nghe lén cookie phiên hoặc đánh cắp token Remember-me trên máy người dùng để mạo danh. | • **Session Fixation Protection**: Tự động cấp Session ID mới khi đăng nhập thành công (`migrateSession`).<br>• **Cookie Security**: Cờ `HttpOnly = true` (chống trộm qua XSS), `SameSite = Lax` (chống CSRF), `Secure = true` trên HTTPS.<br>• **Giới hạn số phiên đồng thời (F8)**: Tối đa 2 phiên/tài khoản (Spring Session). Người dùng có quyền hủy phiên từ xa.<br>• **Persistent Token Rotation (F7)**: Cơ chế Series & Token xoay vòng liên tục theo chuẩn RFC Spring Security; tự động thu hồi ngay khi đổi mật khẩu. | OWASP A07:2021<br>NIST 800-63B §7 |
| **6. Leo thang đặc quyền & Tê liệt Quản trị (Privilege Escalation & Last Admin DoS)** | Kẻ tấn công hoặc Admin vô tình xóa/khóa tài khoản Admin cuối cùng khiến toàn bộ hệ thống bị cô lập. | • **Kiểm tra nghiệp vụ cấp CSDL (F10)**: Kiểm đếm `activeAdminCount` trước mọi hành động Xóa, Vô hiệu hóa (`DISABLE`) hoặc Gỡ bỏ role `ROLE_ADMIN`. Hệ thống từ chối dứt điểm (`IllegalStateException`) nếu vi phạm.<br>• **Phân quyền RBAC nghiêm ngặt**: Bảo vệ controller bằng `@PreAuthorize("hasRole('ADMIN')")`. | OWASP A01:2021<br>CWE-269 |
| **7. Tấn công Ứng dụng Web (CSRF, XSS, SQLi, Clickjacking)** | Giả mạo yêu cầu từ trang khác (CSRF), tiêm mã độc vào giao diện (XSS) hoặc chèn mã SQL. | • **CSRF Protection**: Bật mặc định trên tất cả form POST/PUT/DELETE qua token ẩn của Spring Security.<br>• **Chống SQL Injection**: Sử dụng Spring Data JPA / Hibernate với Prepared Statements & Parameterized Queries.<br>• **Chống XSS**: Công nghệ template Thymeleaf tự động escape HTML khi render dữ liệu.<br>• **Security Headers**: HSTS, Content Security Policy (CSP), `X-Frame-Options: DENY` (chống Clickjacking). | OWASP Top 10 (A03, A05)<br>CWE-79 / CWE-89 |
| **8. Tấn công từ điển & Tái dùng mật khẩu cũ (Dictionary & Password Reuse)** | Người dùng đặt mật khẩu dễ đoán hoặc sử dụng lại mật khẩu cũ đã từng bị lộ. | • **Tra cứu Blacklist (F4)**: Kiểm tra đối chiếu mật khẩu với danh mục OWASP 10.000 mật khẩu phổ biến nhất.<br>• **Lịch sử mật khẩu (Password History)**: Lưu trữ và ngăn chặn sử dụng lại 5 mật khẩu gần nhất của tài khoản. | NIST 800-63B §5.1.1.2 |
| **9. Rò rỉ thông tin nhạy cảm qua Log & Xóa dấu vết (Log Injection & Audit Tampering)** | Kẻ xấu khai thác file log để trộm mật khẩu, hoặc can thiệp nhật ký để xóa dấu vết tấn công. | • **Zero Cleartext Logging**: Tuyệt đối không bao giờ ghi mật khẩu rõ, mã TOTP hoặc Token thô vào Console hay Log file.<br>• **Append-Only Audit Trail (F11)**: Nhật ký kiểm toán được ghi tự động vào bảng riêng (`audit_logs`) với ID, IP, User-Agent, Event Type và Timestamp không thể sửa đổi qua UI người dùng. | OWASP A09:2021<br>NIST SP 800-92 |

---

## 5. CÔNG NGHỆ ÁP DỤNG (TECH STACK)
- **Ngôn ngữ**: Java 25 (LTS)
- **Framework**: Spring Boot 4.1.2, Spring Security 7.1.0 (Lambda DSL), Spring Data JPA
- **Session & JDBC**: Spring Session JDBC, HikariCP
- **Cơ sở dữ liệu**: MySQL 8.4 LTS, H2 Database (In-Memory cho Integration Testing)
- **Bảo mật 2FA**: RFC 6238 TOTP, AES-256-GCM Encryption, ZXing QR Code
- **Giao diện**: Thymeleaf, Bootstrap 5.3, Bootstrap Icons
