package com.fptaptech.auth.web;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordsMatchValidator.class)
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface PasswordsMatch {
    String message() default "Mật khẩu xác nhận không khớp.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
