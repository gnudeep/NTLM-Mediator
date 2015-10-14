package org.wso2.carbon.mediator.ntlm;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.synapse.*;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2SynapseEnvironment;
import org.apache.synapse.mediators.AbstractMediator;

public class NTLMCalloutMediator extends AbstractMediator implements ManagedLifecycle {

    private ConfigurationContext configCtx = null;
    private String serviceURL = null;
    private String action = null;
    private String clientRepository = null;
    private String axis2xml = null;
    private String useServerConfig = null;
    private boolean initClientOptions = true;
    public final static String DEFAULT_CLIENT_REPO = "./samples/axis2Client/client_repo";
    public final static String DEFAULT_AXIS2_XML = "./samples/axis2Client/client_repo/conf/axis2.xml";

    public boolean mediate(MessageContext synCtx) {

        SynapseLog synLog = getLog(synCtx);

        if (synLog.isTraceOrDebugEnabled()) {
            synLog.traceOrDebug("Start : Callout mediator");

            if (synLog.isTraceTraceEnabled()) {
                synLog.traceTrace("Message : " + synCtx.getEnvelope());
            }
        }

        try {
            ServiceClient sc = new ServiceClient(configCtx, null);

            Options options;
            if (initClientOptions) {
                options = new Options();
            } else {
                org.apache.axis2.context.MessageContext axis2MessageCtx =
                        ((Axis2MessageContext) synCtx).getAxis2MessageContext();
                options = axis2MessageCtx.getOptions();
            }

            options.setTo(new EndpointReference(serviceURL));

            if (action != null) {
                options.setAction(action);
            } else {
                if (synCtx.isSOAP11()) {
                    options.setProperty(Constants.Configuration.DISABLE_SOAP_ACTION, true);
                } else {
                    Axis2MessageContext axis2smc = (Axis2MessageContext) synCtx;
                    org.apache.axis2.context.MessageContext axis2MessageCtx =
                            axis2smc.getAxis2MessageContext();
                    axis2MessageCtx.getTransportOut().addParameter(
                            new Parameter(HTTPConstants.OMIT_SOAP_12_ACTION, true));
                }
            }

            options.setProperty(
                    AddressingConstants.DISABLE_ADDRESSING_FOR_OUT_MESSAGES, Boolean.TRUE);
            sc.setOptions(options);

            OMElement request = synCtx.getEnvelope().getBody().getFirstElement();
            if (synLog.isTraceOrDebugEnabled()) {
                synLog.traceOrDebug("About to invoke service : " + serviceURL + (action != null ?
                        " with action : " + action : ""));
                if (synLog.isTraceTraceEnabled()) {
                    synLog.traceTrace("Request message payload : " + request);
                }
            }
            if(synCtx.getEnvelope().getBody().getFirstElement() != null) {
                synCtx.getEnvelope().getBody().getFirstElement().detach();
            }
            OMElement result = null;
            try {
                options.setCallTransportCleanup(true);
                result = sc.sendReceive(request);
            } catch (AxisFault axisFault) {
                handleFault(synCtx, axisFault);
            }

            if (synLog.isTraceTraceEnabled()) {
                synLog.traceTrace("Response payload received : " + result);
            }

            if (result != null) {
                synCtx.getEnvelope().getBody().addChild(result);
            } else {
                synLog.traceOrDebug("Service returned a null response");
            }

        } catch (AxisFault e) {
            handleException("Error invoking service : " + serviceURL +
                    (action != null ? " with action : " + action : ""), e, synCtx);
        }
        synLog.traceOrDebug("End : Callout mediator");
        return true;
    }

    private void handleFault(MessageContext synCtx, AxisFault axisFault) {
        synCtx.setProperty(SynapseConstants.SENDING_FAULT, Boolean.TRUE);
        if (axisFault.getFaultCodeElement() != null) {
            synCtx.setProperty(SynapseConstants.ERROR_CODE,
                    axisFault.getFaultCodeElement().getText());
        } else {
            synCtx.setProperty(SynapseConstants.ERROR_CODE,
                    SynapseConstants.CALLOUT_OPERATION_FAILED);
        }

        if (axisFault.getFaultReasonElement() != null) {
            synCtx.setProperty(SynapseConstants.ERROR_MESSAGE,
                    axisFault.getFaultReasonElement().getText());
        } else {
            synCtx.setProperty(SynapseConstants.ERROR_MESSAGE, "Error while performing " +
                    "the callout operation");
        }

        if (axisFault.getFaultDetailElement() != null) {
            if (axisFault.getFaultDetailElement().getFirstElement() != null) {
                synCtx.setProperty(SynapseConstants.ERROR_DETAIL,
                        axisFault.getFaultDetailElement().getFirstElement());
            } else {
                synCtx.setProperty(SynapseConstants.ERROR_DETAIL,
                        axisFault.getFaultDetailElement().getText());
            }
        }

        synCtx.setProperty(SynapseConstants.ERROR_EXCEPTION, axisFault);
        throw new SynapseException("Error while performing the callout operation", axisFault);
    }

    public void init(SynapseEnvironment synEnv) {
        try {
            if (Boolean.parseBoolean(useServerConfig)) {
                configCtx = ((Axis2SynapseEnvironment) synEnv).getAxis2ConfigurationContext();
            } else {
                configCtx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(
                        clientRepository != null ? clientRepository : DEFAULT_CLIENT_REPO,
                        axis2xml != null ? axis2xml : DEFAULT_AXIS2_XML);
            }
        } catch (AxisFault e) {
            String msg = "Error initializing callout mediator : " + e.getMessage();
            log.error(msg, e);
            throw new SynapseException(msg, e);
        }
    }

    public void destroy() {
        try {
            configCtx.terminate();
        } catch (AxisFault ignore) {}
    }

    public void setServiceURL(String serviceURL) {
        this.serviceURL = serviceURL;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public void setInitAxis2ClientOptions(boolean initClientOptions) {
        this.initClientOptions = initClientOptions;
    }
}
