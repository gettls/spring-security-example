package example.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.function.Supplier;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Bean
	public UserDetailsService userDetailsService(){
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("user")
				.password(bCryptPasswordEncoder.encode("1111"))
				.roles("USER")
				.build());

		manager.createUser(User.withUsername("sys")
				.password(bCryptPasswordEncoder.encode("1111"))
				.roles("SYS")
				.build());

		manager.createUser(User.withUsername("admin")
				.password(bCryptPasswordEncoder.encode("1111"))
				.roles("admin")
				.build());

		return manager;
	}


	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http
				.authorizeRequests()
				.antMatchers("/user").hasRole("USER")
				.antMatchers("/admin/pay").hasRole("ADMIN")
				.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
				.anyRequest().authenticated();

		http	
				.formLogin()
//				.loginPage("/loginPage")
				.defaultSuccessUrl("/")
				.failureUrl("/login")
				.usernameParameter("userId")
				.passwordParameter("password")
				.loginProcessingUrl("/login_proc")
				.successHandler(new AuthenticationSuccessHandler() {
					@Override
					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
						System.out.println("authentication" + authentication.getName());
						response.sendRedirect("/");
					}
				})
				.failureHandler(new AuthenticationFailureHandler() {
					@Override
					public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
						System.out.println("exception " + exception.getMessage());
						response.sendRedirect("/login");
					}
				})
				.permitAll();

		http
				.logout()
				.logoutUrl("/logout")
				.logoutSuccessUrl("/login")
				.addLogoutHandler(new LogoutHandler() {
					@Override
					public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
						HttpSession session = request.getSession();
						session.invalidate();
					}
				})
				.logoutSuccessHandler(new LogoutSuccessHandler() {
					@Override
					public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)throws IOException, ServletException {
						response.sendRedirect("/login");
					}
				})
				.deleteCookies("remember-me");
		
		http
				.rememberMe()
				.rememberMeParameter("remember")
				.tokenValiditySeconds(3600)
				.userDetailsService(userDetailsService());
		
		http
				.sessionManagement()
				.maximumSessions(1)
				.maxSessionsPreventsLogin(true)
				.and()
				.sessionFixation().changeSessionId();

		return http.build();
	}

}
