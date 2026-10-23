package com.fptaptech.auth.web;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordsMatchValidator implements ConstraintValidator<PasswordsMatch, RegistrationForm> {

    @Override
    public boolean isValid(RegistrationForm form, ConstraintValidatorContext context) {
        if (form == null) return true;
        if (form.getPassword() == null || form.getConfirmPassword() == null) {
            return false;
        }
        boolean match = form.getPassword().equals(form.getConfirmPassword());
        if (!match) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Mật khẩu xác nhận không khớp với mật khẩu đã nhập.")
                    .addPropertyNode("confirmPassword")
                    .addConstraintViolation();
        }
        return match;
    }
}
