package org.keycloak.social.lark;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.jboss.logging.Logger;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;


import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.vault.VaultStringSecret;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LarkIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {
    protected static final Logger logger = Logger.getLogger(LarkIdentityProvider.class);

    public static final String AUTH_URL = "https://open.feishu.cn/open-apis/authen/v1/authorize";
    public static final String DEFAULT_SCOPE = "snsapi_login";
    public static final String PROFILE_URL = "https://open.feishu.cn/open-apis/authen/v1/user_info?lang=zh_CN";
    public static final String TOKEN_URL = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token";
    public static final String APP_TOKEN_URL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/";

    public static final String OAUTH2_PARAMETER_CLIENT_ID = "app_id";
    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "app_secret";
    public static final String LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN = "app_access_token";

    public static final String USER_ATTRIBUTE_PHONE_NUMBER = "phone_number";

    public static final String RESPONSE_CODE_SUCCESS = "0";

    public LarkIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {

        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
        if (config.getDefaultScope() == null || config.getDefaultScope().isEmpty()) {
            config.setDefaultScope(this.getDefaultScopes());
        }

    }

    @Override
    public Object callback(RealmModel realm, IdentityProvider.AuthenticationCallback callback, EventBuilder event) {
        return new LarkEndpoint(callback, realm, event, this);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {

        JsonNode userInfo = profile.get("data");
        String unionId = getJsonProperty(userInfo, "union_id");
        BrokeredIdentityContext user = new BrokeredIdentityContext(
                (unionId != null && unionId.length() > 0 ? unionId : getJsonProperty(userInfo, "open_id")));
        String name = getJsonProperty(userInfo, "name");
        String email = getJsonProperty(userInfo, "enterprise_email");
        user.setUsername(Optional.ofNullable(email).orElse("input your email"));
        user.setBrokerUserId(getJsonProperty(userInfo, "user_id"));
        user.setModelUsername(Optional.ofNullable(email).orElse("input your email"));


        user.setUsername(name);
        //user.setName(name);
        user.setEmail(Optional.ofNullable(email).orElse("input your email"));
        user.setIdpConfig(getConfig());
        user.setIdp(this);

        user.setUserAttribute(USER_ATTRIBUTE_PHONE_NUMBER, getJsonProperty(userInfo, "mobile"));

        //user.setLastName(name);
        user.setFirstName(name);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
        try {
            JsonNode profile = mapper.readTree(response);
            String respCode = getJsonProperty(profile, "code");


            if (RESPONSE_CODE_SUCCESS.equals(respCode)) {
                //BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);
                //user.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
                return this.doGetFederatedIdentity(accessToken);
            } else {
                throw new IdentityBrokerException("get user info failed, error：" + JsonSerialization.writeValueAsString(profile));
            }

        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from lark.", e);
        }
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        //user_access_token get user info
        try {
            // profile = SimpleHttp.doGet(getConfig().getUserInfoUrl(), this.session).auth(accessToken).asJson();
            JsonNode profile = SimpleHttp.doGet(getConfig().getUserInfoUrl(), this.session).header("Authorization", "Bearer " + accessToken).asJson();
            String respCode = getJsonProperty(profile, "code");
            if (RESPONSE_CODE_SUCCESS.equals(respCode)) {
                return extractIdentityFromProfile(null, profile);
            } else {
                throw new IdentityBrokerException("get user info failed, error：" + JsonSerialization.writeValueAsString(profile));
            }

        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from github.", e);
        }
    }


    @Override
    protected String extractTokenFromResponse(String response, String tokenName) {
        if (response == null)
            return null;

        if (response.startsWith("{")) {
            try {
                JsonNode jsonResponse = mapper.readTree(response);
                if (jsonResponse.has("data")) {
                    JsonNode data = jsonResponse.get("data");
                    if (data.has(tokenName)) {
                        String s = data.get(tokenName).textValue();
                        if (s == null || s.trim().isEmpty())
                            return null;
                        return s;
                    }
                } else {
                    return null;
                }
            } catch (IOException e) {
                throw new IdentityBrokerException("Could not extract token [" + tokenName + "] from response [" + response + "] due: " + e.getMessage(), e);
            }
        } else {
            Matcher matcher = Pattern.compile(tokenName + "=([^&]+)").matcher(response);

            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        return null;
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();
            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        //logger.debug("FEISHU createAuthorizationUrl");
        final UriBuilder uriBuilder;
        uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl());
        uriBuilder.queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());

        return uriBuilder;
    }

    public String generateAppTokenRequest() throws Exception {
        Map<String, String> appTokenReqBody = new HashMap<>();

        appTokenReqBody.put(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId());
        // Workaround for clientSecret, because secret from getConfig().getClientSecret() is encrypted.
        // Lark ask developer put client secret into request body when invoking API to get app token.
        //String clientSecret = getConfig().getConfig().get("clientsecret");
        String clientSecret = "";
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            clientSecret = vaultStringSecret.get().orElse(getConfig().getClientSecret());
        }
        //appTokenReqBody.put(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret());
        appTokenReqBody.put(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);

        String appTokenResp = SimpleHttp.doPost(APP_TOKEN_URL, session).json(appTokenReqBody).asString();

        if (appTokenResp == null) {
            logger.warn("get app token response is null");
            return null;
        }

        if (appTokenResp.startsWith("{")) {
            try {
                JsonNode node = mapper.readTree(appTokenResp);
                if (node.has(LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN)) {
                    String s = node.get(LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN).textValue();
                    if (s == null || s.trim().isEmpty())
                        return null;
                    return s;
                } else {
                    return null;
                }
            } catch (IOException e) {
                throw new IdentityBrokerException("Could not extract app token [" + LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN + "] from response [" + appTokenResp + "] due: " + e.getMessage(), e);
            }
        } else {
            Matcher matcher = Pattern.compile(LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN + "=([^&]+)").matcher(appTokenResp);

            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        return null;
    }

    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    protected class LarkEndpoint extends Endpoint {
        @Context
        protected IdentityProvider.AuthenticationCallback callback;
        @Context
        protected RealmModel realm;
        @Context
        protected EventBuilder event;
        @Context
        private AbstractOAuth2IdentityProvider provider;
        @Context
        protected KeycloakSession session;
        @Context
        protected ClientConnection clientConnection;
        @Context
        protected HttpHeaders headers;
        @Context
        protected HttpRequest httpRequest;
        @Context
        protected UriInfo uriInfo;

        public LarkEndpoint(IdentityProvider.AuthenticationCallback callback, RealmModel realm, EventBuilder event, AbstractOAuth2IdentityProvider provider) {
            super(callback, realm, event, provider);
            this.callback = callback;
            this.realm = realm;
            this.event = event;
            this.provider = provider;
        }


        @Override
        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            if (error != null) {
                if (error.equals(ACCESS_DENIED)) {
                    logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
                    return callback.error(state);
                } else {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }
            AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);

            try {
                if (authorizationCode != null) {
                    // get app_access_token by clientId and clientSecret
                    String appToken = generateAppTokenRequest();
                    // get access_token and user info
                    String response = generateUserTokenRequest(authorizationCode, appToken).asString();

                    BrokeredIdentityContext federatedIdentity = getFederatedIdentity(response);
                    if (getConfig().isStoreToken()) {
                        if (federatedIdentity.getToken() == null)
                            federatedIdentity.setToken(authorizationCode);
                    }

                    federatedIdentity.setIdpConfig(getConfig());
                    federatedIdentity.setIdp(LarkIdentityProvider.this);
                    federatedIdentity.setAuthenticationSession(authSession);
                    //federatedIdentity.setCode(state);

                    return callback.authenticated(federatedIdentity);
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY,
                    Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }
    }

    public SimpleHttp generateUserTokenRequest(String authorizationCode, String appToken) {
        Map<String, String> requestBody = new HashMap<>();

        requestBody.put(OAUTH2_PARAMETER_CODE, authorizationCode);
        requestBody.put(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);

        return SimpleHttp.doPost(getConfig().getTokenUrl(), session).auth(appToken).json(requestBody);
    }
}