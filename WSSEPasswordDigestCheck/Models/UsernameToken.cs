using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WSSEPasswordDigestCheck.Models
{
    public class UsernameToken
    {
        /// <summary>
        /// Gets or sets the created.
        /// </summary>
        /// <value>
        /// The created.
        /// </value>
        public string Created { get; set; }
        /// <summary>
        /// Gets or sets the username.
        /// </summary>
        /// <value>
        /// The username.
        /// </value>
        public string Username { get; set; }

        /// <summary>
        /// Gets or sets the password string.
        /// </summary>
        /// <value>
        /// The password string.
        /// </value>
        public string Password { get; set; }
        /// <summary>
        /// Gets or sets the type of the password.
        /// </summary>
        /// <value>
        /// The type of the password.
        /// </value>
        public string PasswordType { get; set; }

        /// <summary>
        /// Gets or sets the nonce string.
        /// </summary>
        /// <value>
        /// The nonce string.
        /// </value>
        public string Nonce { get; set; }
        /// <summary>
        /// Gets or sets the type of the nonce encoding.
        /// </summary>
        /// <value>
        /// The type of the nonce encoding.
        /// </value>
        public string NonceEncodingType { get; set; }

        /// <summary>
        /// Gets the password bytes.
        /// </summary>
        /// <value>
        /// The password bytes.
        /// </value>
        public byte[] PasswordBytes
        {
            get
            {
                if (!this.PasswordType.Equals("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"))
                {
                    return null;
                }

                byte[] output = null;
                try
                {
                    output = System.Convert.FromBase64String(this.Password);
                }
                catch (Exception)
                {
                }
                return output;
            }
        }

        /// <summary>
        /// Gets the nonce bytes.
        /// </summary>
        /// <value>
        /// The nonce bytes.
        /// </value>
        public byte[] NonceBytes
        {
            get
            {
                if (!this.NonceEncodingType.Equals("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"))
                {
                    return null;
                }

                byte[] output = null;
                try
                {
                    output = System.Convert.FromBase64String(this.Nonce);
                }
                catch (Exception)
                {
                }
                return output;
            }
        }


        /// <summary>
        /// Gets the created date time.
        /// </summary>
        /// <value>
        /// The created date time.
        /// </value>
        public DateTime? CreatedDateTime
        {
            get
            {
                DateTime output;

                if (!DateTime.TryParse(this.Created, out output) )
                {
                    return null;
                }

                return output;
            }
        }
    }
    
}
