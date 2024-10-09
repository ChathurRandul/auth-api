package com.zr.auth_api.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Map<Class<? extends Exception>, ExceptionResponse> exceptionMappings = new HashMap<>();

    static {
        exceptionMappings.put(BadCredentialsException.class, new ExceptionResponse(401, "The username or password is incorrect"));
        exceptionMappings.put(AccountStatusException.class, new ExceptionResponse(403, "The account is locked"));
        exceptionMappings.put(AccessDeniedException.class, new ExceptionResponse(403, "You are not authorized to access this resource"));
        exceptionMappings.put(SignatureException.class, new ExceptionResponse(403, "The JWT signature is invalid"));
        exceptionMappings.put(ExpiredJwtException.class, new ExceptionResponse(403, "The JWT token has expired"));
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleException(Exception exception) {
        // Log the exception stack trace
        System.err.println("Exception occurred: " + exception.getMessage());

        ExceptionResponse response = exceptionMappings.getOrDefault(
                exception.getClass(),
                new ExceptionResponse(500, "Unknown internal server error.")
        );

        ProblemDetail errorDetail = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(response.status), exception.getMessage());
        errorDetail.setProperty("description", response.description);
        return errorDetail;
    }

    private static class ExceptionResponse {
        final int status;
        final String description;

        ExceptionResponse(int status, String description) {
            this.status = status;
            this.description = description;
        }
    }
}
