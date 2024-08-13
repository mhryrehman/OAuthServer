package com.example.OAuthServer;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain webFilterChainForOAuth(HttpSecurity httpSecurity) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
		httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
		.oidc(Customizer.withDefaults());

		httpSecurity.exceptionHandling(e -> e.authenticationEntryPoint(
				new LoginUrlAuthenticationEntryPoint("/login")
				));
		
		httpSecurity.oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));


		return httpSecurity.build();
	}
	
//	@Bean
//	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
//			new OAuth2AuthorizationServerConfigurer();
//		http.apply(authorizationServerConfigurer);
//
//		authorizationServerConfigurer
//			.oidc(oidc ->
//				oidc
//					.userInfoEndpoint(userInfoEndpoint ->
//						userInfoEndpoint
//							.userInfoRequestConverter(userInfoRequestConverter) 
//							.userInfoRequestConverters(userInfoRequestConvertersConsumer) 
//							.authenticationProvider(authenticationProvider) 
//							.authenticationProviders(authenticationProvidersConsumer) 
//							.userInfoResponseHandler(userInfoResponseHandler) 
//							.errorResponseHandler(errorResponseHandler) 
//							.userInfoMapper(userInfoMapper) 
//					)
//			);
//
//		return http.build();
//	}

	@Order(2)
	@Bean
	public SecurityFilterChain appSecurity(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated())
		.formLogin(Customizer.withDefaults());
		
//		httpSecurity
//          .authorizeHttpRequests(authorizeRequests ->
//              authorizeRequests
//                  .requestMatchers("/oauth2/token").permitAll()
//                  .anyRequest().authenticated())
//          .csrf(request->request.disable())
//          .formLogin(request->request.disable());
		  
		return httpSecurity.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		var user = User.withUsername("yasir").password("1234").authorities("read").build();
		return new InMemoryUserDetailsManager(user);
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient  registerClient = RegisteredClient.withId(UUID.randomUUID().toString())
	        .clientId("yasir")
	        .clientSecret("secret") // store in secret manager
	        .scope(OidcScopes.OPENID)
	        .scope(OidcScopes.PROFILE)
	        .redirectUri("http://spring.io/auth")
	        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
	        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
	        .authorizationGrantTypes(grantType -> {
	            grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
	            grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
	            grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
	            grantType.add(AuthorizationGrantType.PASSWORD); // Add Password Grant Type
	        })
	        .clientSettings(ClientSettings.builder().requireProofKey(true).build())
	        .build();

	    return new InMemoryRegisteredClientRepository(registerClient);
	}
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	    keyPairGenerator.initialize(2048);

	    var keys = keyPairGenerator.generateKeyPair();
	    var publicKey = (RSAPublicKey) keys.getPublic();
	    var privateKey = keys.getPrivate();

	    var rsaKey = new RSAKey.Builder(publicKey)
	        .privateKey(privateKey)
	        .keyID(UUID.randomUUID().toString())
	        .build();

	    JWKSet jwkSet = new JWKSet(rsaKey);
	    return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

}
