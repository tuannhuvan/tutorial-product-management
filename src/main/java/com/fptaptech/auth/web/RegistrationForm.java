package com.fptaptech.auth.web;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@PasswordsMatch
public class RegistrationForm {

    @NotBlank(message = "Vui lòng nhập tên đăng nhập.")
    @Size(min = 4, max = 50, message = "Tên đăng nhập phải có từ 4 đến 50 ký tự.")
    private String username;

    @NotBlank(message = "Vui lòng nhập địa chỉ email.")
    @Email(message = "Địa chỉ email không đúng định dạng.")
    private String email;

    @NotBlank(message = "Vui lòng nhập mật khẩu.")
    @Size(min = 12, message = "Mật khẩu phải chứa ít nhất 12 ký tự.")
    private String password;

    @NotBlank(message = "Vui lòng xác nhận lại mật khẩu.")
    private String confirmPassword;
}
