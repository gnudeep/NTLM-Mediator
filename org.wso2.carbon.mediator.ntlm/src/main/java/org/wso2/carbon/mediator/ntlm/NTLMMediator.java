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

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import java.util.*;

public class NTLMMediator extends AbstractMediator implements ManagedLifecycle {

    private String username;

    private String password;

    private String host;

    private String domain;

    private int maxConnectionManagerCacheSize = 32;

    private Map<String, MultiThreadedHttpConnectionManager> connectionManagerCache = Collections.synchronizedMap
            (
                    new LinkedHashMap<String, MultiThreadedHttpConnectionManager>(16, .75F, true) {
                        @Override
                        public boolean removeEldestEntry(Map.Entry eldest) {
                            //when to remove the eldest entry
                            return size() > maxConnectionManagerCacheSize;   //size exceeded the max allowed
                        }

                        @Override
                        public MultiThreadedHttpConnectionManager put(String key,
                                                                      MultiThreadedHttpConnectionManager value) {
                            if (!containsKey(key)) {
                                synchronized (this) {
                                    if (!containsKey(key)) {
                                        return super.put(key, value);
                                    }
                                }
                            }
                            return get(key);
                        }
                    }
            );


    public void init(SynapseEnvironment synapseEnvironment) {
        //Register the custom NTLM authenticator as an Auth Scheme in HttpClient and set the encoding
        //property of the JCIF lib to ASCII.
        jcifs.Config.setProperty("jcifs.encoding", "ASCII");
        AuthPolicy.registerAuthScheme(AuthPolicy.NTLM, CustomNTLMAuthScheme.class);
    }

    public void destroy() {
    }

    public boolean mediate(MessageContext messageContext) {
        // Instantiate a new Http Authenticator with NTLM Auth Scheme
        HttpTransportProperties.Authenticator authenticator = new HttpTransportProperties.Authenticator();
        List<String> authScheme = new ArrayList<String>();
        authScheme.add(HttpTransportProperties.Authenticator.NTLM);
        authenticator.setAuthSchemes(authScheme);

        // Set the NTLM credentials
        if (username != null) {
            authenticator.setUsername(username);
        } else {
            authenticator.setUsername((String) messageContext.getProperty("username"));
        }

        if (password != null) {
            authenticator.setPassword(password);
        } else {
            authenticator.setPassword((String) messageContext.getProperty("password"));
        }

        if (host != null) {
            authenticator.setHost(host);
        } else {
            authenticator.setHost((String) messageContext.getProperty("host"));
        }

        if (domain != null) {
            authenticator.setDomain(domain);
        } else {
            authenticator.setDomain((String) messageContext.getProperty("domain"));
        }

        // Set the new NTLM authenticator as the authenticator to the Axis2 ServiceClient which
        // will be set at the underlying HttpClient
        org.apache.axis2.context.MessageContext axis2MsgCtxt = getAxis2MessageContext(messageContext);
        axis2MsgCtxt.getOptions().setProperty(HTTPConstants.AUTHENTICATE, authenticator);
        axis2MsgCtxt.getOptions().setProperty(HTTPConstants.CHUNKED, Boolean.FALSE);
        //axis2MsgCtxt.getOptions().setProperty(HTTPConstants.REUSE_HTTP_CLIENT, Boolean.TRUE);

        // Read the MultiThreadedHttpConnectionManager from the cache
        MultiThreadedHttpConnectionManager connectionManager;
        String cacheKey = new StringBuilder().append(authenticator.getUsername()).append("@")
                .append(authenticator.getDomain()).append(":")
                .append(authenticator.getPassword()).toString();
        if (connectionManagerCache.containsKey(cacheKey)) {
            connectionManager = connectionManagerCache.get(cacheKey);
        } else {
            connectionManager = connectionManagerCache.put(cacheKey,
                    new MultiThreadedHttpConnectionManager());
        }
        axis2MsgCtxt.getOptions().setProperty(HTTPConstants.MULTITHREAD_HTTP_CONNECTION_MANAGER,
                connectionManager);

        return true;
    }

    /**
     * Returns the Axis2 Message Context from the Synapse Message Context
     *
     * @param synCtx Synapse MessageContext
     * @return Axis2 MessageContext
     */
    private org.apache.axis2.context.MessageContext getAxis2MessageContext(MessageContext synCtx) {
        Axis2MessageContext axis2smc = (Axis2MessageContext) synCtx;
        org.apache.axis2.context.MessageContext msgCtx = axis2smc.getAxis2MessageContext();
        return msgCtx;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public int getMaxConnectionManagerCacheSize() {
        return maxConnectionManagerCacheSize;
    }

    public void setMaxConnectionManagerCacheSize(int maxConnectionManagerCacheSize) {
        this.maxConnectionManagerCacheSize = maxConnectionManagerCacheSize;
    }
}
