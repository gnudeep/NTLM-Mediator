/*
*Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*WSO2 Inc. licenses this file to you under the Apache License,
*Version 2.0 (the "License"); you may not use this file except
*in compliance with the License.
*You may obtain a copy of the License at
*
*http://www.apache.org/licenses/LICENSE-2.0
*
*Unless required by applicable law or agreed to in writing,
*software distributed under the License is distributed on an
*"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*KIND, either express or implied.  See the License for the
*specific language governing permissions and limitations
*under the License.
*/

package org.wso2.carbon.mediator.ntlm;

import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.auth.*;
import org.apache.commons.httpclient.util.EncodingUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * AuthScheme that delegates the work of reading and writing NTLM messages to
 * the JCIFS implementation
 *
 * directly inspired by org.apache.commons.httpclient.auth.NTLMScheme
 */

public class CustomNTLMAuthScheme implements AuthScheme
{
    /** Log object for this class. */
    private static final Log LOG = LogFactory.getLog(NTLMScheme.class);

    /** NTLM challenge string. */
    private String ntlmChallenge = null;

    private static final int UNINITIATED = 0;
    private static final int INITIATED = 1;
    private static final int TYPE1_MSG_GENERATED = 2;
    private static final int TYPE2_MSG_RECEIVED = 3;
    private static final int TYPE3_MSG_GENERATED = 4;
    private static final int FAILED = Integer.MAX_VALUE;

    /** Authentication process state */
    private int state;

    /**
     * Default constructor for the NTLM authentication scheme.
     *
     * @since 3.0
     */
    public CustomNTLMAuthScheme()
    {
        super();
        this.state = UNINITIATED;
    }

    /**
     * Constructor for the NTLM authentication scheme.
     *
     * @param challenge
     *            The authentication challenge
     *
     * @throws MalformedChallengeException
     *             is thrown if the authentication challenge is malformed
     */
    public CustomNTLMAuthScheme(final String challenge)
            throws MalformedChallengeException
    {
        super();
        processChallenge(challenge);
    }

    /**
     * Processes the NTLM challenge.
     *
     * @param challenge
     *            the challenge string
     *
     * @throws MalformedChallengeException
     *             is thrown if the authentication challenge is malformed
     *
     * @since 3.0
     */
    public void processChallenge(final String challenge)
            throws MalformedChallengeException
    {
        String s = AuthChallengeParser.extractScheme(challenge);
        if (!s.equalsIgnoreCase(getSchemeName()))
        {
            throw new MalformedChallengeException("Invalid NTLM challenge: "
                    + challenge);
        }
        int i = challenge.indexOf(' ');
        if (i != -1)
        {
            s = challenge.substring(i, challenge.length());
            this.ntlmChallenge = s.trim();
            this.state = TYPE2_MSG_RECEIVED;
        }
        else
        {
            this.ntlmChallenge = "";
            if (this.state == UNINITIATED)
            {
                this.state = INITIATED;
            }
            else
            {
                this.state = FAILED;
            }
        }
    }

    /**
     * Tests if the NTLM authentication process has been completed.
     *
     * @return true if Basic authorization has been processed,
     *         false otherwise.
     *
     * @since 3.0
     */
    public boolean isComplete()
    {
        return this.state == TYPE3_MSG_GENERATED || this.state == FAILED;
    }

    /**
     * Returns textual designation of the NTLM authentication scheme.
     *
     * @return ntlm
     */
    public String getSchemeName()
    {
        return "ntlm";
    }

    /**
     * The concept of an authentication realm is not supported by the NTLM
     * authentication scheme. Always returns null.
     *
     * @return null
     */
    public String getRealm()
    {
        return null;
    }

    /**
     * Unsupported.
     */
    public String getID()
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns the authentication parameter with the given name, if available.
     *
     *


     * There are no valid parameters for NTLM authentication so this method
     * always returns null.
     *

     *
     * @param name
     *            The name of the parameter to be returned
     *
     * @return the parameter with the given name
     */
    public String getParameter(String name)
    {
        if (name == null)
        {
            throw new IllegalArgumentException("Parameter name may not be null");
        }
        return null;
    }

    /**
     * Returns true. NTLM authentication scheme is connection based.
     *
     * @return true.
     *
     * @since 3.0
     */
    public boolean isConnectionBased()
    {
        return true;
    }

    /**
     * Unsupported.
     */
    public static String authenticate(
            final NTCredentials credentials, final String challenge)
            throws AuthenticationException
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Unsupported.
     */
    public static String authenticate(
            final NTCredentials credentials, final String challenge,
            String charset) throws AuthenticationException
    {
        throw new UnsupportedOperationException();
    }

    /**
     * Unsupported.
     */
    public String authenticate(
            Credentials credentials, String method, String uri)
            throws AuthenticationException
    {
        throw new UnsupportedOperationException();

    }

    /**
     * Produces NTLM authorization string for the given set of
     * {@link Credentials}.
     *
     * @param credentials
     *            The set of credentials to be used for athentication
     * @param method
     *            The method being authenticated
     *
     * @throws InvalidCredentialsException
     *             if authentication credentials are not valid or not applicable
     *             for this authentication scheme
     * @throws AuthenticationException
     *             if authorization string cannot be generated due to an
     *             authentication failure
     *
     * @return an NTLM authorization string
     *
     * @since 3.0
     */
    public String authenticate(Credentials credentials, HttpMethod method)
            throws AuthenticationException
    {
        LOG.trace("enter NTLMScheme.authenticate (Credentials, HttpMethod)");

        if (this.state == UNINITIATED)
        {
            throw new IllegalStateException(
                    "NTLM authentication process has not been initiated");
        }

        NTCredentials ntcredentials = null;
        try
        {
            ntcredentials = (NTCredentials) credentials;
        }
        catch (ClassCastException e)
        {
            throw new InvalidCredentialsException(
                    "Credentials cannot be used for NTLM authentication: "
                            + credentials.getClass().getName());
        }
        byte[] msgBytes = null;
        String response = null;
        if (this.state == INITIATED)
        {
            Type1Message msg = new Type1Message();
            // @see http://davenport.sourceforge.net/ntlm.html#theType1Message
            // dont' support Unicode
            // negotiate OEM
            // request authentication realm in Type2 response
            // not signed
            // not encrypted
            // not authenticated
            // no lan manager key
            // negotiate NTLM
            msg.setFlags(0x5206);
            msg.setSuppliedWorkstation(ntcredentials.getHost());
            msg.setSuppliedDomain(ntcredentials.getDomain());
            msgBytes = msg.toByteArray();
            this.state = TYPE1_MSG_GENERATED;
        }
        else if (this.state == TYPE2_MSG_RECEIVED)
        {
            byte[] msg2Bytes =
                    Base64.decodeBase64(EncodingUtil.getBytes(
                            this.ntlmChallenge,
                            method.getParams().getCredentialCharset()));
            try
            {
                Type2Message msg2 = new Type2Message(msg2Bytes);
                int flags = Type3Message.NTLMSSP_NEGOTIATE_OEM | Type3Message.NTLMSSP_NEGOTIATE_LM_KEY;

                Type3Message msg3 =
                        new Type3Message(msg2, ntcredentials.getPassword(),
                                ntcredentials.getDomain(), ntcredentials.getUserName(), ntcredentials.getHost(), flags);

                msgBytes = msg3.toByteArray();
            }
            catch (IOException ex)
            {
                throw new AuthenticationException(
                        "unable to parse Type2Message", ex);
            }
            this.state = TYPE3_MSG_GENERATED;
        }
        else
        {
            throw new RuntimeException("failed to authenticate");
        }
        response = EncodingUtil.getAsciiString(Base64.encodeBase64(msgBytes));
        return "NTLM " + response;
    }
}
