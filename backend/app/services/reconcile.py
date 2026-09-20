import json
from datetime import datetime,timezone
from sqlalchemy.orm import Session
from ..models import Node,Inbound,NodeState
def desired_node_state(db:Session,node:Node):
 inbounds=db.query(Inbound).filter(Inbound.node_id==node.id,Inbound.tenant_id==node.tenant_id).all()
 return {"node_id":node.id,"state":"READY" if node.state in {NodeState.ready,NodeState.degraded} else node.state.value,"inbounds":[{"id":i.id,"protocol":i.protocol.value,"interface":i.interface,"listen_port":i.listen_port,"desired_state":i.desired_state} for i in inbounds]}
def reconcile_node(db,node,current):
 desired=desired_node_state(db,node)
 return {"changed":desired!=current,"desired":desired,"current":current}
