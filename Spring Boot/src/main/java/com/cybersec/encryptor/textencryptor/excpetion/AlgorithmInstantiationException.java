package com.cybersec.encryptor.textencryptor.excpetion;

public class AlgorithmInstantiationException extends RuntimeException{
    public AlgorithmInstantiationException() {
    }

    public AlgorithmInstantiationException(String message) {
        super(message);
    }

    public AlgorithmInstantiationException(String message, Throwable cause) {
        super(message, cause);
    }

    public AlgorithmInstantiationException(Throwable cause) {
        super(cause);
    }
}
