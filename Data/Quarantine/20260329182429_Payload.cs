using System;
using System.Runtime.Serialization;

namespace OTPBank.CE.Commons.Channel
{

    [DataContract]
    public class Payload
    {
        [DataMember]
        public Guid ChannelDefinitionId { get; set; }

        [DataMember]
        public string RequestId { get; set; }

        [DataMember]
        public string From { get; set; }

        [DataMember]
        public string To { get; set; }

        [DataMember]
        public Message Message { get; set; }

        [DataMember]
        public string OrganizationId { get; set; }

        [DataMember]
        public MarketingAppContext MarketingAppContext { get; set; }
    }

    public class MarketingAppContext
    {
        public string CustomerJourneyId { get; set; }
        public string UserId { get; set; }
        public string UserEntityType { get; set; }
        public bool IsTestSend { get; set; }
    }
}

