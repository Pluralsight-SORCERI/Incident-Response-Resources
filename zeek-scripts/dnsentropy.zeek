#@load base/protocols/dns

module DNS_Entropy;

export {
  # Create an ID for our new stream. By convention, this is
  # called "LOG".
  redef enum Log::ID += { LOG };

  ## The record type which contains the column fields of the DNS log.
  type Info: record {
    ## The earliest time at which a DNS protocol message over the
    ## associated connection is observed.
    ts:            time               &log;
    ## A unique identifier of the connection to which this DNS message
    ## is being transferred.
    uid:           string             &log;
    ## The connection's 4-tuple of endpoint addresses/ports.
    id:            conn_id            &log;
    ## The transport layer protocol of the connection.
    proto:         transport_proto    &log;
    ## The domain name that is the subject of the DNS query.
    query:         string             &log &optional;
    ## The calculated entropy of the dns query.
    query_entropy: double             &log &optional;
    ## The query type.
    qtype:         count              &log &optional;
    ## The query type name.
    qtype_name:    string             &log &optional;
    ## The response code.
    rcode:         count              &log &optional;
    ## The response code name.
    rcode_name:    string             &log &optional;
    ## The set of resource descriptions in the query answer.
    ans:           vector of string   &log &optional;
    ## The set of entropies for each query answer.
    ans_entropy: vector of double &log &optional;
    ## The highest entropy for the query answer set.
    high_answer_entropy: double &log  &optional;
    ## The total number of resource records in a reply message's
    ## answer section.
    total_ans:      count             &optional;
    };
}

# Optionally, we can add a new field to the connection record so that
# the data we are logging (our "Info" record) will be easily
# accessible in a variety of event handlers.
redef record connection += {
  # By convention, the name of this new field is the lowercase name
  # of the module.
  entropy: Info &optional;
};

# This event is handled at a priority higher than zero so that if
# users modify this stream in another script, they can do so at the
# default priority of zero.
event zeek_init() &priority=5
{
  # Create the stream. This adds a default filter automatically.
  Log::create_stream(DNS_Entropy::LOG, [$columns=Info, $path="dns_entropy"]);
  print "With Pluralsight you can see twice the DNS tunneling.";
}
    
event DNS::log_dns(dns: DNS::Info) 
{
  if (dns$saw_reply == T)
  {
  	#print dns;
    
    local rec: DNS_Entropy::Info;
    rec = [$ts = network_time(), 
          $uid = dns$uid, 
          $id = dns$id,
          $proto = dns$proto];

    if (dns?$query) 
    {
      rec$query = dns$query;
      rec$query_entropy = find_entropy(rec$query)$entropy;
    } 

    if (dns?$qtype) {rec$qtype = dns$qtype;} 
    if (dns?$qtype_name) {rec$qtype_name = dns$qtype_name;} 
    if (dns?$rcode) {rec$rcode = dns$rcode;} 
    if (dns?$rcode_name) {rec$rcode_name = dns$rcode_name;}      

    if (dns?$answers) 
    {
      rec$ans = dns$answers;

      rec$high_answer_entropy = 0;
      local temp: vector of double;
      for (i in rec$ans)
      {
          temp[i] = find_entropy(rec$ans[i])$entropy;
          if (rec$high_answer_entropy < temp[i])
          {
            rec$high_answer_entropy = temp[i];
          }
      }
      rec$ans_entropy = temp;
      rec$total_ans = dns$total_answers;
    }
    local limit = 4.6;
    if (rec$query_entropy > limit) 
	{print "DNS Tunneling! ALERT ALERT ALERT"; 
		print rec$query_entropy, rec$query;}
    #print rec;
    #print "";
    Log::write(DNS_Entropy::LOG, rec);
  }
}
