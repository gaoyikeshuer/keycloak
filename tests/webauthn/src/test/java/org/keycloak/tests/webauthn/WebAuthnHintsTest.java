/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.tests.webauthn;

import java.util.List;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.JavascriptExecutor;

/**
 * Tests that the WebAuthn policy hints reach navigator.credentials.create() and navigator.credentials.get()
 * in the configured order, and are omitted when none are configured.
 */
@KeycloakIntegrationTest
public class WebAuthnHintsTest extends AbstractWebAuthnVirtualTest {

    @Test
    public void registrationWithHints() {
        setHints(List.of("hybrid", "security-key", "client-device"));

        openWebAuthnRegisterPage("hints-registration");
        captureWebAuthnOptions("create");
        webAuthnRegisterPage.clickRegister();

        Assertions.assertEquals(List.of("hybrid", "security-key", "client-device"), getCapturedHints());
    }

    @Test
    public void registrationWithoutHints() {
        // hints configured only for the other policy must not be used by this flow
        setOtherPolicyHints(List.of("hybrid"));

        openWebAuthnRegisterPage("no-hints-registration");
        captureWebAuthnOptions("create");
        webAuthnRegisterPage.clickRegister();

        Assertions.assertNull(getCapturedHints());
    }

    @Test
    public void authenticationWithHints() {
        managedRealm.cleanup().add(RealmResource::logoutAll);

        registerUserWithCredential("hints-authentication");
        setHints(List.of("security-key", "hybrid"));

        openWebAuthnLoginPage("hints-authentication");
        captureWebAuthnOptions("get");
        webAuthnLoginPage.clickAuthenticate();

        Assertions.assertEquals(List.of("security-key", "hybrid"), getCapturedHints());
    }

    @Test
    public void authenticationWithoutHints() {
        managedRealm.cleanup().add(RealmResource::logoutAll);

        registerUserWithCredential("no-hints-authentication");
        // hints configured only for the other policy must not be used by this flow
        setOtherPolicyHints(List.of("hybrid"));

        openWebAuthnLoginPage("no-hints-authentication");
        captureWebAuthnOptions("get");
        webAuthnLoginPage.clickAuthenticate();

        Assertions.assertNull(getCapturedHints());
    }

    @Test
    public void registerAndAuthenticateWithHints() {
        managedRealm.cleanup().add(RealmResource::logoutAll);

        setHints(List.of("security-key", "client-device"));

        registerUserWithCredential("hints-login");
        authenticateUser("hints-login", PASSWORD, true);
    }

    @Test
    public void hintsRoundTrip() {
        Assertions.assertEquals(List.of(), getHints(managedRealm.admin().toRepresentation()));

        setHints(List.of("hybrid", "security-key"));

        RealmRepresentation realmRep = managedRealm.admin().toRepresentation();
        Assertions.assertEquals(List.of("hybrid", "security-key"), getHints(realmRep));
        Assertions.assertEquals(List.of(), getOtherPolicyHints(realmRep));
        // stored as realm attributes, but only exposed through the dedicated fields
        Assertions.assertFalse(realmRep.getAttributes().containsKey("webAuthnPolicyHints"));
        Assertions.assertFalse(realmRep.getAttributes().containsKey("webAuthnPolicyHintsPasswordless"));

        setHints(List.of());

        Assertions.assertEquals(List.of(), getHints(managedRealm.admin().toRepresentation()));
    }

    private void registerUserWithCredential(String username) {
        registerUser(username, PASSWORD, username + "@email", SecretGenerator.getInstance().randomString(24), true);

        Assertions.assertTrue(oAuthClient.parseLoginResponse().isSuccess());
        logout();
    }

    private void openWebAuthnRegisterPage(String username) {
        oAuthClient.openRegistrationForm();
        registerPage.assertCurrent();
        registerPage.register("firstName", "lastName", username + "@email", username, PASSWORD);

        webAuthnRegisterPage.assertCurrent();
    }

    private void openWebAuthnLoginPage(String username) {
        oAuthClient.openLoginForm();
        loginPage.assertCurrent();
        loginPage.fillLogin(username, PASSWORD);
        loginPage.submit();

        webAuthnLoginPage.assertCurrent();
    }

    /**
     * Replaces navigator.credentials.create() or get() with a stub that records the requested publicKey options.
     * The stub never resolves, so the page stays where it is and the recorded options can be read afterwards.
     */
    private void captureWebAuthnOptions(String method) {
        ((JavascriptExecutor) driver.driver()).executeScript(
                "window.kcPublicKey = undefined;" +
                "navigator.credentials." + method + " = function(opts) {" +
                "  window.kcPublicKey = opts.publicKey;" +
                "  return new Promise(function() {});" +
                "};"
        );
    }

    private List<?> getCapturedHints() {
        driver.waiting().until(d -> (Boolean) ((JavascriptExecutor) d).executeScript("return window.kcPublicKey !== undefined;"));
        return (List<?>) ((JavascriptExecutor) driver.driver()).executeScript("return window.kcPublicKey.hints;");
    }

    private void setHints(List<String> hints) {
        managedRealm.updateWithCleanup(r -> isPasswordless()
                ? r.webAuthnPolicyPasswordlessHints(hints)
                : r.webAuthnPolicyHints(hints));
    }

    private void setOtherPolicyHints(List<String> hints) {
        managedRealm.updateWithCleanup(r -> isPasswordless()
                ? r.webAuthnPolicyHints(hints)
                : r.webAuthnPolicyPasswordlessHints(hints));
    }

    private List<String> getHints(RealmRepresentation realmRep) {
        return isPasswordless() ? realmRep.getWebAuthnPolicyPasswordlessHints() : realmRep.getWebAuthnPolicyHints();
    }

    private List<String> getOtherPolicyHints(RealmRepresentation realmRep) {
        return isPasswordless() ? realmRep.getWebAuthnPolicyHints() : realmRep.getWebAuthnPolicyPasswordlessHints();
    }
}
