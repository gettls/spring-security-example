package example.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

	@GetMapping("/")
	public String index(HttpSession httpSession) {
		Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
		SecurityContext authentication2 = (SecurityContext)httpSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		return "hi";
	}

	@GetMapping("/thread")
	public String thread(){

		new Thread(new Runnable() {
			@Override
			public void run() {
				Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
			}
		}).start();

		return "thread";
	}

	@GetMapping("/loginPage")
	public String loginPage() {
		return "loginPage";
	}

	@GetMapping("/user")
	public String user(){
		return "user";
	}

	@GetMapping("/admin/pay")
	public String adminPay(){
		return "adminPay";
	}

	@GetMapping("/admin/**")
	public String admin(){
		return "admin";
	}

	@GetMapping("/denied")
	public String denied(){
		return "Access is denied";
	}

	@GetMapping("/login")
	public String login(){
		return "login";
	}

}
