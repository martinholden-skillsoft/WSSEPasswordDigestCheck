using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace WSSEPasswordDigestCheck.Models
{
    public class Request
    {
        private XmlNode GetNode(XmlDocument doc, string xpath)
        {
            XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("soap", "http://www.w3.org/2003/05/soap-envelope");
            ns.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            ns.AddNamespace("wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

            XmlNode node = doc.SelectSingleNode(xpath, ns);
            return node;
        }

        private string GetNodeValue(XmlDocument doc, string xpath, string attr = null)
        {
            XmlNode node = GetNode(doc, xpath);
            if (node != null)
            {
                if (attr == null)
                {
                    return node.InnerText;
                } else
                {
                    XmlAttribute a = node.Attributes[attr];
                    if (a != null)
                    {
                        return a.Value.ToString();
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Request"/> class.
        /// </summary>
        /// <param name="doc">The XML of the request.</param>
        public Request(XmlDocument doc)
        {
            //Extract TimeStamp

            string createdTimeStamp = GetNodeValue(doc,"//wsu:Timestamp/wsu:Created");
            string expiresTimeStamp = GetNodeValue(doc, "//wsu:Timestamp/wsu:Expires");
            this.timeStamp = new TimeStamp() { Created = createdTimeStamp, Expires = expiresTimeStamp };

            //Extract UsernameToken
            string createdUserNameToken = GetNodeValue(doc, "//wsse:UsernameToken/wsu:Created");
            string usernameUserNameToken = GetNodeValue(doc, "//wsse:UsernameToken/wsse:Username");

            string passwordUserNameToken = GetNodeValue(doc, "//wsse:UsernameToken/wsse:Password");
            string passwordtypeUserNameToken = GetNodeValue(doc, "//wsse:UsernameToken/wsse:Password","Type");

            string nonceUserNameToken = GetNodeValue(doc, "//wsse:UsernameToken/wsse:Nonce");
            string nonceencodingtypeUserNameToken = GetNodeValue(doc, "//wsse:UsernameToken/wsse:Nonce", "EncodingType");

            this.userNameToken = new UsernameToken()
            {
                Created = createdUserNameToken,
                Username = usernameUserNameToken,
                Password = passwordUserNameToken,
                PasswordType = passwordtypeUserNameToken,
                Nonce = nonceUserNameToken,
                NonceEncodingType = nonceencodingtypeUserNameToken
            };

            //Now we want to check that TimeStamp is first child in wsse:Security
            this.timeStampFirst = false;
            var securityNode = GetNode(doc, "//wsse:Security");

            if (securityNode.FirstChild.LocalName.Equals("Timestamp"))
            {
                this.timeStampFirst = true;
            }

        }

        public bool timeStampFirst { get; set; }

        public UsernameToken userNameToken { get; set;}
        public TimeStamp timeStamp { get; set; }

        
    }
}
