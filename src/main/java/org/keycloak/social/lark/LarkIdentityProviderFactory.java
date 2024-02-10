package org.keycloak.social.lark;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * @Author: Closure
 * @Date: 2024/2/10 23:01
 */

public class LarkIdentityProviderFactory extends AbstractIdentityProviderFactory<LarkIdentityProvider>
        implements SocialIdentityProviderFactory<LarkIdentityProvider> {

    public static final String PROVIDER_ID  = "lark";

    @Override
    public String getName() {
        return "飞书";
    }

    @Override
    public LarkIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new LarkIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new OAuth2IdentityProviderConfig();
    }
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
