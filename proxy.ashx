<%@ WebHandler Language="C#" Class="proxy" %>
/*
 |
 |ArcGIS for Canadian Municipalities / ArcGIS pour les municipalités canadiennes
 |Polling Place Locator v10.2.0 / Localisateur de bureau de scrutin v10.2.0
 |This file was written by Esri Canada - Copyright 2013 Esri Canada
 |
 |
 | Licensed under the Apache License, Version 2.0 (the "License");
 | you may not use this file except in compliance with the License.
 | You may obtain a copy of the License at
 |
 |    http://www.apache.org/licenses/LICENSE-2.0
 |
 | Unless required by applicable law or agreed to in writing, software
 | distributed under the License is distributed on an "AS IS" BASIS,
 | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 | See the License for the specific language governing permissions and
 | limitations under the License.
 
  This proxy page does not have any security checks. It is highly recommended
  that a user deploying this proxy page on their web server, add appropriate
  security checks, for example checking request path, username/password, target
  url, etc.
*/
using System;
using System.Drawing;
using System.IO;
using System.Web;
using System.Collections.Generic;
using System.Text;
using System.Xml.Serialization;
using System.Web.Caching;
using System.Collections.Specialized;
using System.Configuration;


/// <summary>
/// Forwards requests to an ArcGIS Server REST resource. Uses information in
/// the proxy.config file to determine properties of the server.
/// </summary>
public class proxy : IHttpHandler {


    public void ProcessRequest(HttpContext context)
    {
        string uri = context.Request.Url.Query.Substring(1);
        System.Diagnostics.Debug.WriteLine(context.Request.UrlReferrer);
        
        
        
        if (uri == "generateToken")
        {
            ProcessAGOLToken(context);
        }
        else if (uri.IndexOf("oauthappid=") == 0) //OAuth2&appID
        {
            ProcessOAuth2(context);
        }
        else
        {
            ProcessNormalRequest(context);
        }
    }
    
    public void ProcessAGOLToken(HttpContext context)
    {
        HttpResponse response1 = context.Response;

        System.Diagnostics.Debug.WriteLine(context.Request.UrlReferrer);
        if (context.Request.UrlReferrer == null)
        {
            response1.StatusCode = 403;
            response1.Close();

            return;
        }

        string permitted_referer = System.Configuration.ConfigurationManager.AppSettings["permitted_referer"];
        
        if (!context.Request.UrlReferrer.OriginalString.Contains(permitted_referer))
        //if (context.Request.UrlReferrer.OriginalString !=  permitted_referer)
        {
            response1.StatusCode = 403;
            response1.Close();

            return;
        }
        
        //string uri = context.Request.Url.Query.Substring(1);
        string uri = "https://www.arcgis.com/sharing/generateToken";
        
        // Create a request using a URL that can receive a post. 
        System.Net.WebRequest request = System.Net.WebRequest.Create(uri);
        // Set the Method property of the request to POST.
        request.Method = "POST";
        // Create POST data and convert it to a byte array.
        string postData = "f=json&referer=organizationname.maps.arcgis.com&request=getToken&username=orgaccountusername&password=orgaccountpassword";
        byte[] byteArray = Encoding.UTF8.GetBytes(postData);
        // Set the ContentType property of the WebRequest.
        request.ContentType = "application/x-www-form-urlencoded";
        // Set the ContentLength property of the WebRequest.
        request.ContentLength = byteArray.Length;
        // Get the request stream.
        Stream dataStream = request.GetRequestStream();
        // Write the data to the request stream.
        dataStream.Write(byteArray, 0, byteArray.Length);
        // Close the Stream object.
        dataStream.Close();
        // Get the response.
        System.Net.WebResponse response = request.GetResponse();
        // Display the status.
        Console.WriteLine(((System.Net.HttpWebResponse)response).StatusDescription);
        // Get the stream containing content returned by the server.
        dataStream = response.GetResponseStream();
        // Open the stream using a StreamReader for easy access.
        StreamReader reader = new StreamReader(dataStream);
        // Read the content.
        string responseFromServer = reader.ReadToEnd();
        // Display the content.
        Console.WriteLine(responseFromServer);
        //((System.Net.HttpWebResponse)response).
        response1.Write(responseFromServer);
      
       // response.Write(responseFromServer);
        //response1.Close();
        // Clean up the streams.
        reader.Close();
        dataStream.Close();
        response.Close();
    }

    public void ProcessOAuth2(HttpContext context)
    {
        HttpResponse response1 = context.Response;
        string appID = context.Request.QueryString["oauthappid"]; //oauthappid  appID
        

        string permitted_referer = System.Configuration.ConfigurationManager.AppSettings["permitted_referer"];
     
        if (!context.Request.UrlReferrer.OriginalString.Contains(permitted_referer))
        {
            response1.StatusCode = 403;
            response1.Close();

            return;
        }
        
        // Get the AppSettings section.
        NameValueCollection appSettings = ConfigurationManager.AppSettings;
        string appSecret = "";
        for (int i = 0; i < appSettings.Count; i++)
        {
            System.Diagnostics.Debug.WriteLine(appSettings.GetKey(i) + "," + appSettings[i]);
            if (appID == appSettings.GetKey(i))
            {
                appSecret = appSettings[i];
                break;
            }
        }

        if (appSecret.Length == 0)
        {

            response1.Write("{\"access_token\" : \"Invalid AppID\", \"expires_in\" : 0 }");
        }
        else
        {

            //string uri = context.Request.Url.Query.Substring(1);
            string uri = "https://www.arcgis.com/sharing/oauth2/token";

            // Create a request using a URL that can receive a post. 
            System.Net.WebRequest request = System.Net.WebRequest.Create(uri);
            // Set the Method property of the request to POST.
            request.Method = "POST";
            // Create POST data and convert it to a byte array.

            //string postData = "client_id=Lh27CEpEXlNcQlqm&client_secret=1ed9a97e71934dc7a6f8c4c9d811b053&grant_type=client_credentials";
            string postData = "client_id=" + appID + "&client_secret=" + appSecret + "&grant_type=client_credentials";
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);
            // Set the ContentType property of the WebRequest.
            request.ContentType = "application/x-www-form-urlencoded";
            // Set the ContentLength property of the WebRequest.
            request.ContentLength = byteArray.Length;
            // Get the request stream.
            Stream dataStream = request.GetRequestStream();
            // Write the data to the request stream.
            dataStream.Write(byteArray, 0, byteArray.Length);
            // Close the Stream object.
            dataStream.Close();
            // Get the response.
            System.Net.WebResponse response = request.GetResponse();
            // Display the status.
            Console.WriteLine(((System.Net.HttpWebResponse)response).StatusDescription);
            // Get the stream containing content returned by the server.
            dataStream = response.GetResponseStream();
            // Open the stream using a StreamReader for easy access.
            StreamReader reader = new StreamReader(dataStream);
            // Read the content.
            string responseFromServer = reader.ReadToEnd();
            // Display the content.
            Console.WriteLine(responseFromServer);
            //((System.Net.HttpWebResponse)response).
            response1.Write(responseFromServer);

            // response.Write(responseFromServer);
            //response1.Close();
            // Clean up the streams.
            reader.Close();
            dataStream.Close();
            response.Close();
        }
    }
    
    public void ProcessNormalRequest (HttpContext context) {

        HttpResponse response = context.Response;

        // Get the URL requested by the client (take the entire querystring at once
        //  to handle the case of the URL itself containing querystring parameters)
        string uri = context.Request.Url.Query.Substring(1);
        // Get token, if applicable, and append to the request
        string token = getTokenFromConfigFile(uri);
        if (!String.IsNullOrEmpty(token))
        {
            if (uri.Contains("?"))
                uri += "&token=" + token;
            else
                uri += "?token=" + token;
        }
            
        System.Net.HttpWebRequest req = (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(uri);
        req.Method = context.Request.HttpMethod;
        req.ServicePoint.Expect100Continue = false;
        req.Referer = context.Request.Headers["referer"];
                
        // Set body of request for POST requests
        if (context.Request.InputStream.Length > 0)
        {
            //byte[] bytes = Encoding.UTF8.GetBytes(postData);
            byte[] bytes = new byte[context.Request.InputStream.Length];
            context.Request.InputStream.Read(bytes, 0, (int)context.Request.InputStream.Length);
            req.ContentLength = bytes.Length;
            
            string ctype = context.Request.ContentType;
            if (String.IsNullOrEmpty(ctype)) {
              req.ContentType = "application/x-www-form-urlencoded";
            }
            else {
              req.ContentType = ctype;
            }
            
            using (Stream outputStream = req.GetRequestStream())
            {
                outputStream.Write(bytes, 0, bytes.Length);
            }
        }
        else {
          req.Method = "GET";
        }
    
        // Send the request to the server
        System.Net.WebResponse serverResponse = null;
        try
        {
            serverResponse = req.GetResponse();
        }
        catch (System.Net.WebException webExc)
        {
            response.StatusCode = 500;
            response.StatusDescription = webExc.Status.ToString();
            response.Write(webExc.Response);
            response.End();
            return;
        }
	
	// Set up the response to the client
        if (serverResponse != null) {
            response.ContentType = serverResponse.ContentType;
            using (Stream byteStream = serverResponse.GetResponseStream())
            {
		// Text response
                if (serverResponse.ContentType.Contains("text") || 
                    serverResponse.ContentType.Contains("json") ||
                    serverResponse.ContentType.Contains("xml"))
                {
                    using (StreamReader sr = new StreamReader(byteStream))
                    {
                        string strResponse = sr.ReadToEnd();
                        response.Write(strResponse);
                    }
                }
                else
                {
                    // Binary response (image, lyr file, other binary file)
                    BinaryReader br = new BinaryReader(byteStream);
                    byte[] outb = br.ReadBytes((int)serverResponse.ContentLength);
                    br.Close();

                    // Tell client not to cache the image since it's dynamic
                    response.CacheControl = "no-cache";

                    // Send the image to the client
                    // (Note: if large images/files sent, could modify this to send in chunks)
                    response.OutputStream.Write(outb, 0, outb.Length);
                }

                
                serverResponse.Close();
            }
        }
        response.End();
    }
 
    public bool IsReusable {
        get {
            return false;
        }
    }

    // Gets the token for a server URL from a configuration file
    // TODO: ?modify so can generate a new short-lived token from username/password in the config file
    private string getTokenFromConfigFile(string uri)
    {
        try
        {
            ProxyConfig config = ProxyConfig.GetCurrentConfig();
            if (config != null)
                return config.GetToken(uri);
            else
                throw new ApplicationException(
                    "Proxy.config file does not exist at application root, or is not readable.");
        }
        catch (InvalidOperationException)
        {
            // Proxy is being used for an unsupported service (proxy.config has mustMatch="true")
            HttpResponse response = HttpContext.Current.Response;
            response.StatusCode = (int)System.Net.HttpStatusCode.Forbidden;
            response.End();
        }
        catch (Exception e)
        {
            if (e is ApplicationException)
                throw e;
            
            // just return an empty string at this point
            // -- may want to throw an exception, or add to a log file
        }
        
        return string.Empty;
    }
}

[XmlRoot("ProxyConfig")]
public class ProxyConfig
{
    #region Static Members

    private static object _lockobject = new object();

    public static ProxyConfig LoadProxyConfig(string fileName)
    {
        ProxyConfig config = null;

        lock (_lockobject)
        {
            if (System.IO.File.Exists(fileName))
            {
                XmlSerializer reader = new XmlSerializer(typeof(ProxyConfig));
                using (System.IO.StreamReader file = new System.IO.StreamReader(fileName))
                {
                    config = (ProxyConfig)reader.Deserialize(file);
                }
            }
        }

        return config;
    }

    public static ProxyConfig GetCurrentConfig()
    {
        ProxyConfig config = HttpRuntime.Cache["proxyConfig"] as ProxyConfig;
        if (config == null)
        {
            string fileName = GetFilename(HttpContext.Current);
            config = LoadProxyConfig(fileName);

            if (config != null)
            {
                CacheDependency dep = new CacheDependency(fileName);
                HttpRuntime.Cache.Insert("proxyConfig", config, dep);
            }
        }

        return config;
    }

    public static string GetFilename(HttpContext context)
    {
        return context.Server.MapPath("~/proxy.config");
    }
    #endregion

    ServerUrl[] serverUrls;
    bool mustMatch;

    [XmlArray("serverUrls")]
    [XmlArrayItem("serverUrl")]
    public ServerUrl[] ServerUrls
    {
        get { return this.serverUrls; }
        set { this.serverUrls = value; }
    }

    [XmlAttribute("mustMatch")]
    public bool MustMatch
    {
        get { return mustMatch; }
        set { mustMatch = value; }
    }

    public string GetToken(string uri)
    {
        foreach (ServerUrl su in serverUrls)
        {
            if (su.MatchAll && uri.StartsWith(su.Url, StringComparison.InvariantCultureIgnoreCase))
            {
                return su.Token;
            }
            else
            {
                if (String.Compare(uri, su.Url, StringComparison.InvariantCultureIgnoreCase) == 0)
                    return su.Token;
            }
        }

        if (mustMatch)
            throw new InvalidOperationException();

        return string.Empty;
    }
}

public class ServerUrl
{
    string url;
    bool matchAll;
    string token;

    [XmlAttribute("url")]
    public string Url
    {
        get { return url; }
        set { url = value; }
    }

    [XmlAttribute("matchAll")]
    public bool MatchAll
    {
        get { return matchAll; }
        set { matchAll = value; }
    }

    [XmlAttribute("token")]
    public string Token
    {
        get { return token; }
        set { token = value; }
    }
}
