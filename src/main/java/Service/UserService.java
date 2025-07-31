package Service;

import Model.dto.RegisterRequest;
import Model.entity.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
    
    /**
     * Registers a new user
     * @param registerRequest The registration request
     * @throws IllegalArgumentException if username or email already exists
     */
    void registerUser(RegisterRequest registerRequest);
    
    /**
     * Finds a user by username
     * @param username The username to search for
     * @return The user if found
     * @throws RuntimeException if user not found
     */
    User findByUsername(String username);
    
    /**
     * Finds a user by email
     * @param email The email to search for
     * @return The user if found
     * @throws RuntimeException if user not found
     */
    User findByEmail(String email);
    
    /**
     * Checks if a username exists
     * @param username The username to check
     * @return true if username exists, false otherwise
     */
    boolean existsByUsername(String username);
    
    /**
     * Checks if an email exists
     * @param email The email to check
     * @return true if email exists, false otherwise
     */
    boolean existsByEmail(String email);
} 