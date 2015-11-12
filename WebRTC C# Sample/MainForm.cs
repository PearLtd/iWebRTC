﻿/*
Copyright 2014 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.IO;
using System.Data;
using System.Linq;
using System.Text;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Collections.Generic;
using OpenSource.WebRTC;
using System.Net;

namespace WebRTC_Sample
{
    public partial class MainForm : Form
    {
        private SimpleRendezvousServer mServer;
        private Dictionary<string, RendezvousData> eventTable = new Dictionary<string, RendezvousData>();
        private string htmlpage = null, passiveHtmlpage = null;
        private Dictionary<string, SessionForm> userForms = new Dictionary<string, SessionForm>();
        private bool StunServersInUse = false;
        private string[] StunServers = { "stun.ekiga.net", "stun.ideasip.com", "stun.schlund.de", "stunserver.org", "stun.softjoys.com", "stun.voiparound.com", "stun.voipbuster.com", "stun.voipstunt.com", "stun.voxgratia.org" };

        public MainForm()
        {
            InitializeComponent();
            try
            {
                htmlpage = File.ReadAllText("webrtcsample.html");
                passiveHtmlpage = File.ReadAllText("webrtcpassivesample.html");
                mServer = new SimpleRendezvousServer();
                mServer.OnGet = OnGet;
                mServer.OnPost = OnPost;
                serverStatusLabel.Text = "Running";
                serverLinkLabel.Text = "http://127.0.0.1:" + mServer.Port.ToString() + "/start";
                serverLinkLabel_passive.Text = "http://127.0.0.1:" + mServer.Port.ToString() + "/passive";
            }
            catch (Exception) { serverStatusLabel.Text = "Error"; }

        }

        private void GetNewPassivePOC(WebRTCCommons.CustomAwaiter<byte[]> awaiter)
        {
            BeginInvoke((Action<WebRTCCommons.CustomAwaiter<byte[]>>)(async (a) =>
                {
                    SessionForm f = new SessionForm();
                    if (StunServersInUse) { f.SetStunServers(false, StunServers); }
                    f.FormClosing += SessionFormClosing;
                    f.Show(this);

                    userForms.Add("/" + f.Value.ToString(), f);

                    string content = passiveHtmlpage.Replace("/*{{{ICESERVERS}}}*/", "").Replace("{{{OFFER_URL}}}", "127.0.0.1:" + mServer.Port.ToString() + "/" + f.Value.ToString());
                    string sdp = await f.GetOffer();

                    content = content.Replace("/*{{{SDP}}}*/", System.Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(sdp)));

                    string header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " + content.Length.ToString() + "\r\n\r\n";
                    a.SetComplete(UTF8Encoding.UTF8.GetBytes(header + content));
                }), awaiter);
        }
        private void GetNewPOC(IPEndPoint from, WebRTCCommons.CustomAwaiter<byte[]> awaiter)
        {
            BeginInvoke((Action<IPEndPoint, WebRTCCommons.CustomAwaiter<byte[]>>)((origin, a) =>
                {
                    SessionForm f = new SessionForm();
                    if (StunServersInUse) { f.SetStunServers(false, StunServers); }
                    f.FormClosing += SessionFormClosing;
                    f.Show(this);

                    userForms.Add("/" + f.Value.ToString(), f);

                    string content = htmlpage.Replace("/*{{{ICESERVERS}}}*/", "").Replace("{{{OFFER_URL}}}", origin.Address.ToString() + ":" + mServer.Port.ToString() + "/" + f.Value.ToString());
                    string header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: " + content.Length.ToString() + "\r\n\r\n";
                    a.SetComplete(UTF8Encoding.UTF8.GetBytes(header + content));
                }), from, awaiter);

        }

        void SessionFormClosing(object sender, FormClosingEventArgs e)
        {
            SessionForm f = sender as SessionForm;
            userForms.Remove("/" + f.Value.ToString());
        }

        private WebRTCCommons.CustomAwaiter<byte[]> OnPost(SimpleRendezvousServer sender, string path, string body)
        {
            return (userForms[path].GetOfferResponse(body));
        }

        private WebRTCCommons.CustomAwaiter<byte[]> OnGet(SimpleRendezvousServer sender, IPEndPoint from, string path)
        {
            WebRTCCommons.CustomAwaiter<byte[]> retVal = new WebRTCCommons.CustomAwaiter<byte[]>();

            switch (path)
            {
                case "/start":
                    GetNewPOC(from, retVal);
                    break;
                case "/passive":
                    GetNewPassivePOC(retVal);
                    break;
                default:
                    retVal.SetComplete(UTF8Encoding.UTF8.GetBytes("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"));
                    break;
            }

            return (retVal);
        }

        public class RendezvousData
        {
            public ManualResetEvent waitHandle = new ManualResetEvent(false);
            public byte[] inData = null;
            public byte[] outData = null;
        }

        private void browserButton_Click(object sender, EventArgs e)
        {
            System.Diagnostics.Process.Start(serverLinkLabel.Text);
        }

        private void serverLinkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start(serverLinkLabel.Text);
        }

        private void closeButton_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void infoLinkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start("http://" + infoLinkLabel.Text);
        }

        private void stunSettingsButton_Click(object sender, EventArgs e)
        {
            using (StunSettingsForm f = new StunSettingsForm())
            {
                f.StunServers = StunServers;
                f.StunServersInUse = StunServersInUse;
                if (f.ShowDialog(this) == System.Windows.Forms.DialogResult.OK)
                {
                    StunServersInUse = f.StunServersInUse;
                    if (StunServersInUse) { StunServers = f.StunServers; stunLabel.Text = StunServers.Length.ToString() + " server(s) in use"; } else { stunLabel.Text = "Disabled"; }
                }
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {

        }

        private void serverLinkLabel_passive_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            System.Diagnostics.Process.Start(serverLinkLabel_passive.Text);
        }
    }
}
