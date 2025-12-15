/**
 * Copyright © 2016-2025 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.service.security.auth.oauth2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.thingsboard.server.common.data.id.OAuth2ClientId;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.data.id.UserId;
import org.thingsboard.server.common.data.oauth2.OAuth2Client;
import org.thingsboard.server.dao.oauth2.OAuth2ClientService;
import org.thingsboard.server.dao.oauth2.OAuth2User;
import org.thingsboard.server.dao.user.UserService;
import org.thingsboard.server.queue.util.TbCoreComponent;
import org.thingsboard.server.service.security.model.OAuth2SessionValidationResponse;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Service
@TbCoreComponent
@RequiredArgsConstructor
public class OAuth2SessionValidator {

    private final OAuth2ClientService oAuth2ClientService;
    private final OAuth2ClientMapperProvider oauth2ClientMapperProvider;
    private final UserService userService;
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Validates the OAuth2 session by checking if the refresh token is still valid
     * and if the user identity matches the current logged-in user.
     *
     * @param oauth2RefreshToken The OAuth2 refresh token
     * @param oauth2ClientId The OAuth2 client ID
     * @param currentUserId The current logged-in user ID
     * @return OAuth2SessionValidationResponse containing validation result
     */
    public OAuth2SessionValidationResponse validateSession(String oauth2RefreshToken, String oauth2ClientId, UserId currentUserId) {
        log.info("[OAuth2 Session] Validation request received for user: {}, clientId: {}", currentUserId, oauth2ClientId);
        try {
            if (StringUtils.isEmpty(oauth2RefreshToken) || StringUtils.isEmpty(oauth2ClientId)) {
                log.debug("[OAuth2 Session] Validation skipped - missing refresh token or client ID");
                return OAuth2SessionValidationResponse.builder()
                        .valid(true) // Not an OAuth2 session, skip validation
                        .build();
            }

            // Load OAuth2 client configuration
            log.debug("[OAuth2 Session] Loading OAuth2 client configuration for clientId: {}", oauth2ClientId);
            OAuth2Client oauth2Client = oAuth2ClientService.findOAuth2ClientById(
                    TenantId.SYS_TENANT_ID,
                    new OAuth2ClientId(UUID.fromString(oauth2ClientId))
            );

            if (oauth2Client == null) {
                log.warn("[OAuth2 Session] OAuth2 client not found: {}", oauth2ClientId);
                return OAuth2SessionValidationResponse.builder()
                        .valid(false)
                        .reason("OAuth2 client not found")
                        .build();
            }

            log.debug("[OAuth2 Session] OAuth2 client found: {}", oauth2Client.getName());

            // Try to refresh the access token using the refresh token
            log.debug("[OAuth2 Session] Attempting to refresh access token");
            OAuth2AccessTokenResponse tokenResponse = refreshAccessToken(oauth2Client, oauth2RefreshToken);
            
            if (tokenResponse == null) {
                log.info("[OAuth2 Session] Session invalid - unable to refresh token for user: {}", currentUserId);
                return OAuth2SessionValidationResponse.builder()
                        .valid(false)
                        .reason("Session expired or invalid")
                        .build();
            }

            log.debug("[OAuth2 Session] Access token refreshed successfully");

            // Get user info from the new access token using the mapper
            String accessTokenValue = tokenResponse.getAccessToken().getTokenValue();
            
            // Fetch user information from OAuth2 provider using the access token
            log.debug("[OAuth2 Session] Fetching user information from OAuth2 provider");
            OAuth2User oauth2User;
            try {
                oauth2User = fetchOAuth2UserInfo(oauth2Client, accessTokenValue);
            } catch (Exception e) {
                log.error("[OAuth2 Session] Error fetching OAuth2 user info for user: {}", currentUserId, e);
                return OAuth2SessionValidationResponse.builder()
                        .valid(false)
                        .reason("Unable to retrieve user information")
                        .build();
            }

            if (oauth2User == null || StringUtils.isEmpty(oauth2User.getEmail())) {
                log.warn("[OAuth2 Session] Unable to retrieve user info from OAuth2 provider for user: {}", currentUserId);
                return OAuth2SessionValidationResponse.builder()
                        .valid(false)
                        .reason("Unable to retrieve user information")
                        .build();
            }

            log.debug("[OAuth2 Session] OAuth2 user info retrieved: {}", oauth2User.getEmail());

            // Get current user's email for comparison
            String currentUserEmail = userService.findUserById(TenantId.SYS_TENANT_ID, currentUserId).getEmail();
            
            // Check if the user has changed
            boolean userChanged = !oauth2User.getEmail().equalsIgnoreCase(currentUserEmail);
            
            if (userChanged) {
                log.info("[OAuth2 Session] User mismatch detected - current: {}, OAuth2: {}", 
                        currentUserEmail, oauth2User.getEmail());
                return OAuth2SessionValidationResponse.builder()
                        .valid(false)
                        .reason("User has changed")
                        .userChanged(true)
                        .build();
            }

            log.info("[OAuth2 Session] Session validation successful for user: {}", currentUserId);

            // Session is valid, return new tokens
            return OAuth2SessionValidationResponse.builder()
                    .valid(true)
                    .newAccessToken(tokenResponse.getAccessToken().getTokenValue())
                    .newRefreshToken(tokenResponse.getRefreshToken() != null ? 
                            tokenResponse.getRefreshToken().getTokenValue() : oauth2RefreshToken)
                    .build();

        } catch (Exception e) {
            log.error("[OAuth2 Session] Unexpected error validating OAuth2 session for user: {}", currentUserId, e);
            return OAuth2SessionValidationResponse.builder()
                    .valid(false)
                    .reason("Validation error: " + e.getMessage())
                    .build();
        }
    }

    /**
     * Refreshes the OAuth2 access token using the refresh token
     */
    private OAuth2AccessTokenResponse refreshAccessToken(OAuth2Client oauth2Client, String refreshToken) {
        log.debug("[OAuth2 Session] Refreshing access token for client: {}", oauth2Client.getName());
        try {
            String tokenUri = oauth2Client.getAccessTokenUri();
            String clientId = oauth2Client.getClientId();
            String clientSecret = oauth2Client.getClientSecret();

            log.debug("[OAuth2 Session] Token URI: {}", tokenUri);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            // Add Basic Auth if client secret is present
            if (!StringUtils.isEmpty(clientSecret)) {
                String auth = clientId + ":" + clientSecret;
                byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes());
                String authHeader = "Basic " + new String(encodedAuth);
                headers.set("Authorization", authHeader);
            }

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "refresh_token");
            params.add("refresh_token", refreshToken);
            
            if (StringUtils.isEmpty(clientSecret)) {
                params.add("client_id", clientId);
            }

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            log.debug("[OAuth2 Session] Sending token refresh request to OAuth2 provider");
            ResponseEntity<String> response = restTemplate.exchange(
                    tokenUri,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.debug("[OAuth2 Session] Token refresh successful");
                JsonNode jsonNode = objectMapper.readTree(response.getBody());
                
                String accessToken = jsonNode.get("access_token").asText();
                String newRefreshToken = jsonNode.has("refresh_token") ? 
                        jsonNode.get("refresh_token").asText() : refreshToken;
                long expiresIn = jsonNode.has("expires_in") ? 
                        jsonNode.get("expires_in").asLong() : 3600;

                return OAuth2AccessTokenResponse.withToken(accessToken)
                        .tokenType(OAuth2AccessToken.TokenType.BEARER)
                        .expiresIn(expiresIn)
                        .refreshToken(newRefreshToken)
                        .build();
            }

            log.warn("[OAuth2 Session] Token refresh failed - received non-2xx response or empty body");
            return null;
        } catch (Exception e) {
            log.error("[OAuth2 Session] Error refreshing OAuth2 access token", e);
            return null;
        }
    }

    /**
     * Fetches OAuth2 user information from the provider using the access token
     */
    private OAuth2User fetchOAuth2UserInfo(OAuth2Client oauth2Client, String accessToken) {
        log.debug("[OAuth2 Session] Fetching user info from OAuth2 provider for client: {}", oauth2Client.getName());
        try {
            String userInfoUri = oauth2Client.getUserInfoUri();
            if (StringUtils.isEmpty(userInfoUri)) {
                log.warn("[OAuth2 Session] User info URI not configured for OAuth2 client: {}", oauth2Client.getId());
                return null;
            }

            log.debug("[OAuth2 Session] User info URI: {}", userInfoUri);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> request = new HttpEntity<>(headers);

            log.debug("[OAuth2 Session] Sending user info request to OAuth2 provider");
            ResponseEntity<String> response = restTemplate.exchange(
                    userInfoUri,
                    HttpMethod.GET,
                    request,
                    String.class
            );

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                log.debug("[OAuth2 Session] User info retrieved successfully");
                JsonNode userInfoNode = objectMapper.readTree(response.getBody());
                
                // Use the mapper to convert JSON to OAuth2User
                OAuth2ClientMapper mapper = oauth2ClientMapperProvider.getOAuth2ClientMapperByType(
                        oauth2Client.getMapperConfig().getType()
                );
                
                // Extract basic user info from the response
                OAuth2User oauth2User = new OAuth2User();
                
                // Get email from the configured attribute or default "email"
                String emailAttributeKey = oauth2Client.getMapperConfig().getBasic() != null &&
                        !StringUtils.isEmpty(oauth2Client.getMapperConfig().getBasic().getEmailAttributeKey()) ?
                        oauth2Client.getMapperConfig().getBasic().getEmailAttributeKey() : "email";
                
                if (userInfoNode.has(emailAttributeKey)) {
                    oauth2User.setEmail(userInfoNode.get(emailAttributeKey).asText());
                }
                
                // Get first name
                String firstNameAttributeKey = oauth2Client.getMapperConfig().getBasic() != null &&
                        !StringUtils.isEmpty(oauth2Client.getMapperConfig().getBasic().getFirstNameAttributeKey()) ?
                        oauth2Client.getMapperConfig().getBasic().getFirstNameAttributeKey() : "given_name";
                
                if (userInfoNode.has(firstNameAttributeKey)) {
                    oauth2User.setFirstName(userInfoNode.get(firstNameAttributeKey).asText());
                }
                
                // Get last name
                String lastNameAttributeKey = oauth2Client.getMapperConfig().getBasic() != null &&
                        !StringUtils.isEmpty(oauth2Client.getMapperConfig().getBasic().getLastNameAttributeKey()) ?
                        oauth2Client.getMapperConfig().getBasic().getLastNameAttributeKey() : "family_name";
                
                if (userInfoNode.has(lastNameAttributeKey)) {
                    oauth2User.setLastName(userInfoNode.get(lastNameAttributeKey).asText());
                }
                
                return oauth2User;
            }

            log.warn("[OAuth2 Session] Failed to fetch user info - received non-2xx response or empty body");
            return null;
        } catch (Exception e) {
            log.error("[OAuth2 Session] Error fetching OAuth2 user info from provider", e);
            return null;
        }
    }
}
