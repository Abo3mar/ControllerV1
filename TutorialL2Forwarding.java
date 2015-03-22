/*
 * Copyright (C) 2014 SDN Hub

 Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
 You may not use this file except in compliance with this License.
 You may obtain a copy of the License at

    http://www.gnu.org/licenses/gpl-3.0.txt

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 implied.

 *
 */

package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Date;
import java.sql.Timestamp;
import java.sql.SQLException;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.lang.String;
import java.util.Map;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.packet.ARP;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.ICMP;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.Flood;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.sal.utils.NetUtils;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.switchmanager.Subnet;

import java.sql.Connection;

import JDBC.*;

import java.math.BigInteger;
import java.sql.Time;
import java.text.SimpleDateFormat;
public class TutorialL2Forwarding implements IListenDataPacket {
    private static final Logger logger = LoggerFactory
            .getLogger(TutorialL2Forwarding.class);
    private ISwitchManager switchManager = null;
    private IFlowProgrammerService programmer = null;
    private IDataPacketService dataPacketService = null;
    private Map<Long, NodeConnector> mac_to_port = new HashMap<Long, NodeConnector>();
    private String function = "switch";
    private jdbcQuery con = new jdbcQuery();
    private multi_Type rules = null;
    boolean verbous = true;	//Used to enable or disable extensive commenting
    //private Connection Database = con.Connect();
    void setDataPacketService(IDataPacketService s) {
        this.dataPacketService = s;
    }

    void unsetDataPacketService(IDataPacketService s) {
        if (this.dataPacketService == s) {
            this.dataPacketService = null;
        }
    }

    public void setFlowProgrammerService(IFlowProgrammerService s)
    {
        this.programmer = s;
    }

    public void unsetFlowProgrammerService(IFlowProgrammerService s) {
        if (this.programmer == s) {
            this.programmer = null;
        }
    }

    void setSwitchManager(ISwitchManager s) {
        logger.debug("SwitchManager set");
        this.switchManager = s;
    }

    void unsetSwitchManager(ISwitchManager s) {
        if (this.switchManager == s) {
            logger.debug("SwitchManager removed!");
            this.switchManager = null;
        }
    }

    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */
    void init() {
        logger.info("Initialized");
        // Disabling the SimpleForwarding and ARPHandler bundle to not conflict with this one
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        for(Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getSymbolicName().contains("simpleforwarding")) {
                try {
                    bundle.uninstall();
                } catch (BundleException e) {
                    logger.error("Exception in Bundle uninstall "+bundle.getSymbolicName(), e); 
                }   
            }   
        }   
 
    }

    /**
     * Function called by the dependency manager when at least one
     * dependency become unsatisfied or when the component is shutting
     * down because for example bundle is being stopped.
     *
     */
    void destroy() {
    }

    /**
     * Function called by dependency manager after "init ()" is called
     * and after the services provided by the class are registered in
     * the service registry
     *
     */
    void start() {
        logger.info("Started");
    }

    /**
     * Function called by the dependency manager before the services
     * exported by the component are unregistered, this will be
     * followed by a "destroy ()" calls
     *
     */
    void stop() {
        logger.info("Stopped");
    }

    private void floodPacket(RawPacket inPkt) {
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();

        Set<NodeConnector> nodeConnectors =
                this.switchManager.getUpNodeConnectors(incoming_node);

        for (NodeConnector p : nodeConnectors) {
            if (!p.equals(incoming_connector)) {
                try {
                    RawPacket destPkt = new RawPacket(inPkt);
                    destPkt.setOutgoingNodeConnector(p);
                    this.dataPacketService.transmitDataPacket(destPkt);
                } catch (ConstructionException e2) {
                    continue;
                }
            }
        }
    }
    
    // JACQUIE ***************************** START MODIFICATION
/**
 * checks to determine if the current time is within the time frame the 
 * MAC has been granted access to the internet.    
 * @return a value of 10 (equivalent to 10sec) or 0 meaning no access
 */
private int calcTimeOut(){
	
	if(verbous){
		logger.info("Calculating timeout");
	}
	long timenow = System.currentTimeMillis();
	//SimpleDateFormat now = new SimpleDateFormat("T");
	 //logger.info("time now: " +now);
	java.sql.Time time =  new Time(timenow);
	if(verbous){
		logger.info("Before = "+time.after(rules.getStopTime())+" After ="+time.after(rules.getStartTime()));
		logger.info("ST = "+rules.getStartTime()+" STOPTIME = "+rules.getStopTime()+" Time now = "+time);
	}
	if(rules.getStartTime() == null){
		if(verbous){
			logger.info("Return Result = 60");
		}
		return(60);
	}else if (!time.before(rules.getStopTime()) && time.after(rules.getStartTime())){
		if(verbous){
			logger.info("Return Result = 10");
		}
		return(10); 
	}else{
		if(verbous){
			logger.info("Return Result = 0");
			//logger.info("calcTimeOut timeNOW = "+time+"notime"+nolimit);
		}
	    return(0);
	}
	
} 
	//JACQUIE ***************************** END MODIFICATION

/*
 * This method returns the maximum allowable time (mat) limit for a user
 * the (mat) number will be used to set the OVS' hardtimeOut field.
 * 
 * This allows us to force the user to come back to the controller after 
 * the hardtimeOut expires, once the user contact the controller, the 
 * controller will re-check maximum allowable time.
 */
private long userUsageAlgorithm(){
	
	long bandwidth = rules.getBandwidth();				// In bits/secs
	long userCurrentUsage = rules.getUsrUsage();		// In bytes
	long userUsageLimit = rules.getUsrUsageLimit();		// In bytes
	if(verbous){
		logger.info("Calculating Maximum Usage Time ");
		logger.info("BW = "+bandwidth+" User Current Usage = "+userCurrentUsage+" User Usage Limit = " + userUsageLimit);
	}
	// Calculating Hardtime out for a "user"
	long userHardTimeout = (userUsageLimit - userCurrentUsage)/(bandwidth/8);
	
	return userHardTimeout;
}


/*
 * This method returns the maximum allowable time (mat) limit for the 
 * entire network the (mat) number will be used to set the OVS' hardtimeOut 
 * field.
 * 
 *this allows us to make sure that the total usage limit is always guarded and
 *never exceeded
 */
private long totalUsageAlgorithm(){
	long totalbandwidth = rules.getTotalBandwidth();	// In bits/secs
	long totalCurrentUsage = rules.getNetworkUsage();	// In bytes
	long totalUsageLimit = rules.getTotalDataLimit();	// In bytes
	if(verbous){
		logger.info("Calculating Maximum Usage Time ");
		logger.info("Total BW = "+totalbandwidth+" Total Current Usage = "+totalCurrentUsage+" Total Usage Limit = "+totalUsageLimit);
	}
	// Calculating Hardtime out for "Entire Network"
	long totalHardTimeout = (totalUsageLimit - totalCurrentUsage)/(totalbandwidth/8);
	return totalHardTimeout;
}

@Override
public PacketResult receiveDataPacket(RawPacket inPkt) {
	
	boolean block = true;
	if (inPkt == null) {
		return PacketResult.IGNORED;
    }

	NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        
	long time_out_start_stop = 0;	//Time available for Start_time and Stop_time
	long time_out_total_usage = 0;	//Time available for the entire network download capacity
	long time_out_user_usage = 0;	//Time available per user download capacity
	long min_time_out = 0;	//Time out variable after finishing the precedence rule		
	
	// Hub implementation
	if (function.equals("hub")) {
		floodPacket(inPkt);
	} else {
		Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);
		if (!(formattedPak instanceof Ethernet)) {
			return PacketResult.IGNORED;
		}
		NodeConnector outgoing_connector = knowDestinationMAC(formattedPak);
		// JACQUIE ***************************** START MODIFICATION
		boolean needsFlowRules = learnSourceMAC(formattedPak, incoming_connector);
		// JACQUIE ***************************** END MODIFICATION
		
		// JACQUIE ***************************** START MODIFICATION
		//Check for time out value 
		if (needsFlowRules){
			block = rules.getBlock();
			/*
			 * We need to check the time for:
			 * 	1. Start - Stop time 
			 * 	2. Total network allowable usage
			 *  3. User allowable usage
			 *  
			 */
			time_out_start_stop = calcTimeOut();	
			time_out_total_usage = userUsageAlgorithm();
			time_out_user_usage = totalUsageAlgorithm();
			min_time_out = time_out_start_stop;	//Assume "time_out_start_stop" the lowest
			
			// Calculate the minimum time
			if(time_out_total_usage < min_time_out){
				min_time_out = time_out_total_usage;
			} else if(time_out_user_usage < min_time_out){
				min_time_out = time_out_total_usage;
			}
			// Because we can can only have a "short" timeout variable we want to cut the min_time_out if it exceed 32767 secs
			if(min_time_out > 32767){
				min_time_out = 32767;
			}
			if(verbous){
				logger.info("Possible Hard Timeouts: "+time_out_start_stop+"-"+time_out_total_usage+"-"+time_out_user_usage);
				logger.info("Minimum timeout: "+min_time_out);
			}
		} 
		// JACQUIE ***************************** END MODIFICATION
		
		if (outgoing_connector == null) {
			floodPacket(inPkt);
		} else {
			//JACQUIE ***************************** START MODIFICATION
			if (!programFlow(formattedPak, incoming_connector,
				outgoing_connector, block, min_time_out )) {
				return PacketResult.IGNORED;
			} 
			//JACUQIE ***************************** END MODIFICATION
            inPkt.setOutgoingNodeConnector(outgoing_connector);
            this.dataPacketService.transmitDataPacket(inPkt);
            }
        }
	return PacketResult.CONSUME;
}

    private boolean learnSourceMAC(Packet formattedPak, NodeConnector incoming_connector) {

    	
    	byte[] srcMAC = ((Ethernet)formattedPak).getSourceMACAddress();
        long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
        this.mac_to_port.put(srcMAC_val, incoming_connector);
        
    	// JACQUIE ***************************** START MODIFICATION
    	rules = null;
        rules = con.Connect(srcMAC_val);  // Connect to database
    	if(verbous){
    		//logger.info("macRules = "+rules.getBlock()+" "+rules.getStartTime());
    		logger.info("Rules = "+(rules==null));
    	}
        return (rules != null); // If true then rules must be checked, where true means there are rules
        						//associated with the source MAC (srcMAC_val)
       // JACQUIE ***************************** END MODIFICATION
    }
	
    private NodeConnector knowDestinationMAC(Packet formattedPak) {
        byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();
        long dstMAC_val = BitBufferHelper.toNumber(dstMAC);
        return this.mac_to_port.get(dstMAC_val) ;
    }
    
    // JACQUIE ***************************** START MODIFICATION
    /******************************************************
     * Stops flow if rule is not 0
     * @param rule from check_MAC_rule true = block
     * @param out the asking output node
     * @return Output
     */
    private Output DesignFlow(Boolean block, NodeConnector outgoing_connector){
    	if (!block){
    		return	(new Output(outgoing_connector));	//Sets outgoing connector for packets to be forwarded
    	}else{	
    		return (new Output(null));	//Sets outgoing connector to null to drop packtes
    	}
    }
    // JACQUIE ***************************** END MODIFICATION

    // JACQUIE MODIFICATION >> Addition of new parameters: (boolean rule and long timeOUT)
    private boolean programFlow(Packet formattedPak, 
            					NodeConnector incoming_connector, 
            					NodeConnector outgoing_connector, 
            					boolean block,
            					long timeOUT) {
    	//int temp = 0;
        byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();
        //byte[] srcMAC = ((Ethernet)formattedPak).getSourceMACAddress();
       
        Match match = new Match();
        match.setField(new MatchField(MatchType.IN_PORT, incoming_connector) );
        match.setField(new MatchField(MatchType.DL_DST, dstMAC.clone()) );

        
        List<Action> actions = new ArrayList<Action>();
        // JACQUIE ***************************** START MODIFICATION
        Flow f = null;
        if(block == true || timeOUT == 0){
        	/**
        	 * Drops packet if rules are not satisfied 
        	 */
        	actions.add(0, null);
        	f = new Flow(match, actions);
        	f.setHardTimeout((short)5);
        	if(verbous){
        		logger.info("DROP!!");
        	}
        }else{
        	/**
        	 * Installs flow with respect to calculated rule restrictions 
        	 */
        	actions.add(DesignFlow(block, outgoing_connector)); //<<<< RIGHT NOW
        	f = new Flow(match, actions);
        	if(verbous){
        		logger.info("installing Flow {}",incoming_connector);
        	}
        	f.setHardTimeout((short)timeOUT); //Time out based on rule calculation
        }	
        // JACQUIE ***************************** END MODIFICATION
        // Modify the flow on the network node
        Node incoming_node = incoming_connector.getNode();
        Status status = programmer.addFlow(incoming_node, f);

        if (!status.isSuccess()) {
            logger.warn("SDN Plugin failed to program the flow: {}. The failure is: {}",
                    f, status.getDescription());
            return false;
        } else {
            return true;
        }
    }
}
