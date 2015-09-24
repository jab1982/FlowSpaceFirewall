package edu.iu.grnoc.flowspace_firewall;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.action.OFAction;

public class Sanitizer {

    private HashMap<Long, ArrayList<OFMatch>> match_rejects;
    private HashMap<Long, ArrayList<OFAction>> action_rejects;

    public Sanitizer(){
        this.match_rejects = new HashMap<Long, ArrayList<OFMatch>>();
        this.action_rejects = new HashMap<Long, ArrayList<OFAction>>();
    }


    public ArrayList<OFMatch> getMatchRejects(Long DPID){
        return this.match_rejects.get(DPID);
    }

    public ArrayList<OFAction> getActionRejects(Long DPID){
        return this.action_rejects.get(DPID);
    }

    public void setMatchRejects(Long DPID, ArrayList<OFMatch> value){
        this.match_rejects.put(DPID, value);
    }

    public void setActionRejects(Long DPID, ArrayList<OFAction> value){
        this.action_rejects.put(DPID, value);
    }

    public boolean checkFlowMod(Long DPID, OFMessage msg){
        OFFlowMod tmpFlow = (OFFlowMod)msg;

        if(tmpFlow.getCommand() == OFFlowMod.OFPFC_ADD || tmpFlow.getCommand() == OFFlowMod.OFPFF_CHECK_OVERLAP
                || tmpFlow.getCommand() == OFFlowMod.OFPFC_MODIFY || tmpFlow.getCommand() == OFFlowMod.OFPFC_MODIFY_STRICT){

            OFMatch match = tmpFlow.getMatch();
            ArrayList<OFMatch> matchRejects = this.getMatchRejects(DPID);

            Iterator<OFMatch> it = matchRejects.iterator();
            while(it.hasNext()){
                OFMatch matchReject = it.next();

                if (subsumes(matchReject, match)){

                    // compare fild by field
                    // Log....
                    return false;
                }

            }

            List<OFAction> actions = tmpFlow.getActions();
            ArrayList<OFAction> actionsRejects = getActionRejects(DPID);
            if(actions.equals(actionsRejects)){
                // Log
                return false;
            }
        }
        return true;
    }


    /** From openflowj 1.0.2
     * Check whether the explicit match subsumes a more generic match.
     *
     * The explicit match subsumes the generic match if each field in this
     * object either:
     * <ol>
     *   <li> exactly matches the corresponding field in the other match
     *   <li> the field is wildcarded in this object
     * </ol>
     * Note: The network source and destination wildcards must have fewer
     * or the same number of bits wildcarded in this object as the other.
     *
     * @param match explicitcMatch used for comparison when checking subsumes
     * @param match genericMatch used for comparison when checking subsumes
     * @return boolean indicating whether this match subsumes another match
     */
    public boolean subsumes(OFMatch explicitMatch, OFMatch genericMatch) {
        // L1
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_IN_PORT) == 0) {
            if (explicitMatch.getInputPort() != genericMatch.getInputPort()) {
                return false;
            }
        }

        // L2
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_DL_DST) == 0) {
            if (!Arrays.equals(explicitMatch.getDataLayerDestination(), genericMatch.getDataLayerDestination())) {
                return false;
            }
        }
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_DL_SRC) == 0) {
            if (!Arrays.equals(explicitMatch.getDataLayerSource(), genericMatch.getDataLayerSource())) {
                return false;
            }
        }
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_DL_TYPE) == 0) {
            if (explicitMatch.getDataLayerType() != genericMatch.getDataLayerType()) {
                return false;
            }
        }
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_DL_VLAN) == 0) {
            if (explicitMatch.getDataLayerVirtualLan()!= genericMatch.getDataLayerVirtualLan()) {
                return false;
            }
        }
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_DL_VLAN_PCP) == 0) {
            if (explicitMatch.getDataLayerVirtualLanPriorityCodePoint() != genericMatch.getDataLayerVirtualLanPriorityCodePoint()) {
                return false;
            }
        }

        // L3
        int maskLen = explicitMatch.getNetworkDestinationMaskLen();
        if (maskLen > genericMatch.getNetworkDestinationMaskLen()) {
            return false;
        }
        int mask = (maskLen == 0) ? 0 : (0xffffffff << (32 - maskLen));
        if ((explicitMatch.getNetworkDestination() & mask) != (genericMatch.getNetworkDestination() & mask)) {
            return false;
        }
        maskLen = explicitMatch.getNetworkSourceMaskLen();
        if (maskLen > genericMatch.getNetworkSourceMaskLen()) {
            return false;
        }
        mask = (maskLen == 0) ? 0 : (0xffffffff << (32 - maskLen));
        if ((explicitMatch.getNetworkSource() & mask) != (genericMatch.getNetworkSource() & mask)) {
            return false;
        }
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_NW_PROTO) == 0) {
            if (explicitMatch.getNetworkProtocol() != genericMatch.getNetworkProtocol()) {
                return false;
            }
        }
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_NW_TOS) == 0) {
            if (explicitMatch.getNetworkTypeOfService() != genericMatch.getNetworkTypeOfService()) {
                return false;
            }
        }

        // L4
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_TP_DST) == 0) {
            if (explicitMatch.getTransportDestination() != genericMatch.getTransportDestination()) {
                return false;
            }
        }
        if ((explicitMatch.getWildcards() & OFMatch.OFPFW_TP_SRC) == 0) {
            if (explicitMatch.getTransportSource() != genericMatch.getTransportSource()) {
                return false;
            }
        }

        return true;
    }
}
