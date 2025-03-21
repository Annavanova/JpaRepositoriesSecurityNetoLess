package jpadb.JpaRepositoriesDemo.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ControllerSecurity {
    @Secured("ROLE_READ")
    @GetMapping("/read")
    public String read() {
        return "Read content";
    }

    @RolesAllowed("ROLE_WRITE")
    @GetMapping("/write")
    public String write() {
        return "Write content";
    }

    @PreAuthorize("hasAnyRole('WRITE', 'DELETE')")
    @GetMapping("/modify")
    public String modify() {
        return "Modify content";
    }

    @GetMapping("/match")
    public String match(@RequestParam String username) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName().equals(username)) {
            return "Matched Username content";
        }
        return "No Match";
    }
}
