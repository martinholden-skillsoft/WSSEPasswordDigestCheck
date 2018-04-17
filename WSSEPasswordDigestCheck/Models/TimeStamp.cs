using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WSSEPasswordDigestCheck.Models
{
    public class TimeStamp
    {
        /// <summary>
        /// Gets or sets the created.
        /// </summary>
        /// <value>
        /// The created.
        /// </value>
        public string Created { get; set; }
        /// <summary>
        /// Gets or sets the expires.
        /// </summary>
        /// <value>
        /// The expires.
        /// </value>
        public string Expires { get; set; }

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

                if (!DateTime.TryParse(this.Created, out output))
                {
                    return null;
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
        public DateTime? ExpiresDateTime
        {
            get
            {
                DateTime output;

                if (!DateTime.TryParse(this.Expires, out output))
                {
                    return null;
                }

                return output;
            }
        }
    }
}
