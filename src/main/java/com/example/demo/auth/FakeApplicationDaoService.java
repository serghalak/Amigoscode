package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        Optional<ApplicationUser> first = getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
        return first;
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser>applicationUsers= Lists.newArrayList(
                new ApplicationUser(STUDENT.getGrantedAuthorities()
                        ,passwordEncoder.encode("password")
                        ,"annasmith"
                        ,true
                        ,true
                        ,true
                        ,true),
                new ApplicationUser(ADMIN.getGrantedAuthorities()
                        ,passwordEncoder.encode("password")
                        ,"linda"
                        ,true
                        ,true
                        ,true
                        ,true),
                new ApplicationUser(ADMINTRAINER.getGrantedAuthorities()
                        ,passwordEncoder.encode("password")
                        ,"tom"
                        ,true
                        ,true
                        ,true
                        ,true)
        );
        return applicationUsers;
    }
}
