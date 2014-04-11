////
//   NLog.Targets.Syslog
//   ------------------------------------------------------------------------
//   Copyright 2013 Jesper Hess Nielsen <jesper@graffen.dk>
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
////

// ReSharper disable CheckNamespace
namespace NLog.Targets
// ReSharper restore CheckNamespace
{
    using System;
    using System.Linq;
    using System.Text;
    using System.Reflection;
    using System.Threading;
    using System.Net;
    using System.Net.Sockets;
    using System.Globalization;
    using System.Net.Security;
    using System.IO;

    /// <summary>
    /// This class enables logging to a unix-style syslog server using NLog.
    /// </summary>
    [Target("Syslog")]
    public class Syslog : TargetWithLayout
    {
        /// <summary>
        /// Sets the IP Address or Host name of your Syslog server
        /// </summary>
        public string SyslogServer { get; set; }

        /// <summary>
        /// Sets the Port number syslog is running on (usually 514)
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Sets the name of the application that will show up in the syslog log
        /// </summary>
        public string Sender { get; set; }

        /// <summary>
        /// Sets the syslog facility name to send messages as (for example, local0 or local7)
        /// </summary>
        public SyslogFacility Facility { get; set; }

        /// <summary>
        /// Sets the syslog server protocol (tcp/udp) 
        /// </summary>
        public ProtocolType Protocol { get; set; }

        /// <summary>
        /// If this is set, try to configure and use SSL if available.
        /// </summary>
        public bool Ssl { get; set; }

        /// <summary>
        /// Initializes a new instance of the Syslog class
        /// </summary>
        public Syslog()
        {
            // Sensible defaults...
            SyslogServer = "127.0.0.1";
            Port = 514;
            Sender = Assembly.GetCallingAssembly().GetName().Name;
            Facility = SyslogFacility.Local1;
            Protocol = ProtocolType.Udp;
        }

        /// <summary>
        /// This is where we hook into NLog, by overriding the Write method. 
        /// </summary>
        /// <param name="logEvent">The NLog.LogEventInfo </param>
        protected override void Write(LogEventInfo logEvent)
        {            
            // Store the current UI culture
            CultureInfo currentCulture = Thread.CurrentThread.CurrentCulture;
            // Set the current Locale to "en-US" for proper date formatting
            Thread.CurrentThread.CurrentCulture = new CultureInfo("en-US");

            //byte[] message = BuildSyslogMessage(Facility, GetSyslogSeverity(logEvent.Level), DateTime.Now, Sender, Layout.Render(logEvent));
            //SendMessage(SyslogServer, Port, message, Protocol, Ssl);

            SyslogSeverity level = GetSyslogSeverity(logEvent.Level);
            var messageBody = Layout.Render(logEvent);

            string[] messageBodyLines = messageBody.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (byte[] message in messageBodyLines.Select(messageBodyLine => BuildSyslogMessage(Facility, level, Sender, messageBodyLine)))
            {
                SendMessage(SyslogServer, Port, message, Protocol, Ssl);
            }


            // Restore the original culture
            Thread.CurrentThread.CurrentCulture = currentCulture;
        }

        /// <summary>
        /// Performs the actual network part of sending a message
        /// </summary>
        /// <param name="logServer">The syslog server's host name or IP address</param>
        /// <param name="port">The UDP port that syslog is running on</param>
        /// <param name="msg">The syslog formatted message ready to transmit</param>
        /// <param name="protocol">The syslog server protocol (tcp/udp)</param>
        /// <param name="useSsl"></param>
        private static void SendMessage(string logServer, int port, byte[] msg, ProtocolType protocol, bool useSsl = false)
        {
            var logServerIp = Dns.GetHostAddresses(logServer).FirstOrDefault();
            if (logServerIp == null) return;
            
            var ipAddress = logServerIp.ToString();

            switch (protocol)
            {
                case ProtocolType.Udp:
                    var udp = new UdpClient(ipAddress, port);
                    udp.Send(msg, msg.Length);
                    udp.Close();
                    break;
                case ProtocolType.Tcp:
                    var tcp = new TcpClient(ipAddress, port);
                    Stream stream;
                    if (useSsl)
                    {
                        var sslStream = new SslStream(tcp.GetStream());
                        sslStream.AuthenticateAsClient(logServer);
                        stream = sslStream;
                    }
                    else
                    {
                        stream = tcp.GetStream();
                    }

                    stream.Write(msg, 0, msg.Length);

                    stream.Close();
                    tcp.Close();
                    break;
                default:
                    throw new NLogConfigurationException(string.Format("Protocol '{0}' is not supported.", protocol));
            }
        }

        /// <summary>
        /// Mapping between NLog levels and syslog severity levels as they are not exactly one to one. 
        /// </summary>
        /// <param name="logLevel">NLog log level to translate</param>
        /// <returns>SyslogSeverity which corresponds to the NLog level. </returns>
        private static SyslogSeverity GetSyslogSeverity(LogLevel logLevel)
        {
            if (logLevel == LogLevel.Fatal)
            { 
                return SyslogSeverity.Emergency; 
            }
            
            if (logLevel >= LogLevel.Error)
            {
                return SyslogSeverity.Error;
            }
            
            if (logLevel >= LogLevel.Warn)
            { 
                return SyslogSeverity.Warning; 
            }
            
            if (logLevel >= LogLevel.Info)
            {
                return SyslogSeverity.Informational;
            }
            
            if (logLevel >= LogLevel.Debug)
            {
                return SyslogSeverity.Debug;
            }
            
            if (logLevel >= LogLevel.Trace)
            {
                return SyslogSeverity.Notice; 
            }
            
            return SyslogSeverity.Notice;
        }

        private static byte[] BuildSyslogMessage(SyslogFacility facility, SyslogSeverity level, string sender,
            string messageBody)
        {

            int priority = CalculatePriority(facility, level);
            string message = string.Format("<{0}>{1} {2} {3}: {4}{5}",
                priority,
                DateTime.Now.ToString("MMM dd HH:mm:ss"),
                Dns.GetHostName(),
                sender.Substring(0, 32),
                messageBody,
                Environment.NewLine);

            return Encoding.ASCII.GetBytes(message);
        }

        /// <summary>
        /// Calculates the Syslog priority value.
        /// </summary>
        /// <param name="facility">The facility.</param>
        /// <param name="level">The level.</param>
        /// <returns></returns>
        private static int CalculatePriority(SyslogFacility facility, SyslogSeverity level)
        {
            // Priority = Facility * 8 + Level
            return (int)facility * 8 + (int)level;
        }

    }
}
