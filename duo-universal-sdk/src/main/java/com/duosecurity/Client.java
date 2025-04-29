package com.duosecurity;

import static com.duosecurity.Utils.createJwt;
import static com.duosecurity.Utils.createJwtForAuthUrl;
import static com.duosecurity.Utils.getAndValidateUrl;
import static com.duosecurity.Utils.transformDecodedJwtToToken;
import static com.duosecurity.Utils.validateCaCert;
import static com.duosecurity.Validator.validateClientParams;
import static com.duosecurity.Validator.validateState;
import static com.duosecurity.Validator.validateUsername;
import static java.lang.String.format;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.HealthCheckResponse;
import com.duosecurity.model.Token;
import com.duosecurity.model.TokenResponse;
import com.duosecurity.service.DuoConnector;


/**
 * Client serves as the entry point for this library. Instantiating this class
 * gives access to four public methods required for Duo's Universal Prompt 2FA.
 */
public class Client {

  // **************************************************
  // Constants
  // **************************************************
  private static final String OAUTH_V_1_HEALTH_CHECK_ENDPOINT = "/oauth/v1/health_check";

  private static final String OAUTH_V_1_AUTHORIZE_ENDPOINT = "/oauth/v1/authorize";

  private static final String OAUTH_V_1_TOKEN_ENDPOINT = "/oauth/v1/token";

  private static final String CLIENT_ASSERTION_TYPE
        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  private static final String USER_AGENT_LIB = "duo_universal_java";

  private static final String USER_AGENT_VERSION = "1.2.1-SNAPSHOT";

  // **************************************************
  // Fields
  // **************************************************
  private String clientId;

  private String clientSecret;

  private String apiHost;

  private String redirectUri;

  private Boolean useDuoCodeAttribute;

  private String proxyHost;

  private Integer proxyPort;

  protected DuoConnector duoConnector;

  private String userAgent;

  // **************************************************
  // Constructors
  // This class uses the "Builder" pattern and should not be directly instantiated.
  // Use Client.Builder to generate the Client.
  // **************************************************

  private Client() {
  }

  /**
   * Legacy simple constructor.
   * @param clientId This value is the client id provided by Duo in the admin panel.
   * @param clientSecret This value is the client secret provided by Duo in the admin panel.
   * @param apiHost This value is the api host provided by Duo in the admin panel.
   * @param redirectUri This value is the uri which Duo should redirect to after 2FA is completed.
   *
   * @throws DuoException For problems building the client
   * @deprecated The constructors are deprecated.
   *     Prefer the {@link Client.Builder} for instantiating Clients
   */
  @Deprecated
  public Client(String clientId, String clientSecret, String apiHost, String redirectUri)
      throws DuoException {
    this(clientId, clientSecret, apiHost, redirectUri, null);
  }

  /**
   * Legacy constructor which allows specifying custom CaCerts.
   * @param clientId This value is the client id provided by Duo in the admin panel.
   * @param clientSecret This value is the client secret provided by Duo in the admin panel.
   * @param apiHost This value is the api host provided by Duo in the admin panel.
   * @param redirectUri This value is the uri which Duo should redirect to after 2FA is completed.
   * @param userCaCerts This value is a list of CA Certificates used to validate connections to Duo
   *
   * @throws DuoException For problems building the client
   * 
   * @deprecated The constructors are deprecated.
   *     Prefer the {@link Client.Builder} for instantiating Clients
   */
  @Deprecated
  public Client(String clientId, String clientSecret, String apiHost,
              String redirectUri, String[] userCaCerts) throws DuoException {
    Client client = new Builder(clientId, clientSecret, apiHost, redirectUri)
            .setCACerts(userCaCerts)
            .build();
    this.clientId = client.clientId;
    this.clientSecret = client.clientSecret;
    this.apiHost = client.apiHost;
    this.redirectUri = client.redirectUri;
    this.useDuoCodeAttribute = client.useDuoCodeAttribute;
    this.duoConnector = client.duoConnector;
    this.userAgent = client.userAgent;
  }

  /**
   * Legacy constructor which allows specifying custom CaCerts.
   *
   * @param clientId     This value is the client id provided by Duo in the admin
   *                     panel.
   * @param clientSecret This value is the client secret provided by Duo in the
   *                     admin panel.
   * @param apiHost      This value is the api host provided by Duo in the admin panel.
   * @param redirectUri  This value is the uri which Duo should redirect to after
   *                     2FA is completed.
   * @param proxyHost    This value is the hostname of the proxy server
   * @param proxyPort    This value is the port number of the proxy server
   * @param userCaCerts  This value is a list of CA Certificates used to validate connections to Duo
   *
   * @throws DuoException For problems building the client
   *
   * @deprecated The constructors are deprecated. Prefer the
   *             {@link Client.Builder} for instantiating Clients
   */
  @Deprecated
  public Client(String clientId, String clientSecret, String apiHost,
                String redirectUri, String proxyHost, Integer proxyPort,
                String[] userCaCerts) throws DuoException {
    Client client = new Builder(clientId, clientSecret, proxyHost, proxyPort, apiHost, redirectUri)
            .setCACerts(userCaCerts)
            .build();
    this.clientId = client.clientId;
    this.clientSecret = client.clientSecret;
    this.apiHost = client.apiHost;
    this.redirectUri = client.redirectUri;
    this.useDuoCodeAttribute = client.useDuoCodeAttribute;
    this.duoConnector = client.duoConnector;
    this.userAgent = client.userAgent;
    this.proxyHost = client.proxyHost;
    this.proxyPort = client.proxyPort;
  }

  public static class Builder {
    private final String clientId;
    private final String clientSecret;
    private final String apiHost;
    private String proxyHost;
    private Integer proxyPort;
    private final String redirectUri;
    private Boolean useDuoCodeAttribute;
    private String[] caCerts;
    private String userAgent;

    private static final String[] DEFAULT_CA_CERTS = {
    // Source URL: https://www.amazontrust.com/repository/AmazonRootCA1.cer
    // Certificate 1 Details:
    // Original Format: DER
    // Subject: CN=Amazon Root CA 1,O=Amazon,C=US
    // Issuer: CN=Amazon Root CA 1,O=Amazon,C=US
    // Expiration Date: 2038-01-17 00:00:00
    // Serial Number: 66C9FCF99BF8C0A39E2F0788A43E696365BCA
    // SHA256 Fingerprint: 8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e
    "sha256/MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsFADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXjca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qwIFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQmjgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUAA4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDIU5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUsN+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vvo/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpyrqXRfboQnoZsG4q5WTP468SQvvG5",
    // Source URL: https://www.amazontrust.com/repository/AmazonRootCA2.cer
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=Amazon Root CA 2,O=Amazon,C=US
    // Issuer: CN=Amazon Root CA 2,O=Amazon,C=US
    // Expiration Date: 2040-05-26 00:00:00
    // Serial Number: 66C9FD29635869F0A0FE58678F85B26BB8A37
    // SHA256 Fingerprint: 1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4
    "sha256/MIIFQTCCAymgAwIBAgITBmyf0pY1hp8KD+WGePhbJruKNzANBgkqhkiG9w0BAQwFADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAyMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK2Wny2cSkxKgXlRmeyKy2tgURO8TW0G/LAIjd0ZEGrHJgw12MBvIITplLGbhQPDW9tK6Mj4kHbZW0/jTOgGNk3Mmqw9DJArktQGGWCsN0R5hYGCrVo34A3MnaZMUnbqQ523BNFQ9lXg1dKmSYXpN+nKfq5clU1Imj+uIFptiJXZNLhSGkOQsL9sBbm2eLfq0OQ6PBJTYv9K8nu+NQWpEjTj82R0Yiw9AElaKP4yRLuH3WUnAnE72kr3H9rN9yFVkE8P7K6C4Z9r2UXTu/Bfh+08LDmG2j/e7HJV63mjrdvdfLC6HM783k81ds8P+HgfajZRRidhW+mez/CiVX18JYpvL7TFz4QuK/0NURBs+18bvBt+xa47mAExkv8LV/SasrlX6avvDXbR8O70zoan4G7ptGmh32n2M8ZpLpcTnqWHsFcQgTfJU7O7f/aS0ZzQGPSSbtqDT6ZjmUyl+17vIWR6IF9sZIUVyzfpYgwLKhbcAS4y2j5L9Z469hdAlO+ekQiG+r5jqFoz7Mt0Q5X5bGlSNscpb/xVA1wf+5+9R+vnSUeVC06JIglJ4PVhHvG/LopyboBZ/1c6+XUyo05f7O0oYtlNc/LMgRdg7c3r3NunysV+Ar3yVAhU/bQtCSwXVEqY0VThUWcI0u1ufm8/0i2BWSlmy5A5lREedCf+3euvAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSwDPBMMPQFWAJI/TPlUq9LhONmUjANBgkqhkiG9w0BAQwFAAOCAgEAqqiAjw54o+Ci1M3m9Zh6O+oAA7CXDpO8Wqj2LIxyh6mx/H9z/WNxeKWHWc8w4Q0QshNabYL1auaAn6AFC2jkR2vHat+2/XcycuUY+gn0oJMsXdKMdYV2ZZAMA3m3MSNjrXiDCYZohMr/+c8mmpJ5581LxedhpxfL86kSk5Nrp+gvU5LEYFiwzAJRGFuFjWJZY7attN6a+yb3ACfAXVU3dJnJUH/jWS5E4ywl7uxMMne0nxrpS10gxdr9HIcWxkPo1LsmmkVwXqkLN1PiRnsn/eBG8om3zEK2yygmbtmlyTrIQRNg91CMFa6ybRoVGld45pIq2WWQgj9sAq+uEjonljYE1x2igGOpm/HlurR8FLBOybEfdF849lHqm/osohHUqS0nGkWxr7JOcQ3AWEbWaQbLU8uz/mtBzUF+fUwPfHJ5elnNXkoOrJupmHN5fLT0zLm4BwyydFy4x2+IoZCn9Kr5v2c69BoVYh63n749sSmvZ6ES8lgQGVMDMBu4Gon2nL2XA46jCfMdiyHxtN/kHNGfZQIG6lzWE7OE76KlXIx3KadowGuuQNKotOrN8I1LOJwZmhsoVLiJkO/KdYE+HvJkJMcYr07/R54H9jVlpNMKVv/1F2Rs76giJUmTtt8AF9pYfl3uxRuw0dFfIRDH+fO6AgonB8Xx1sfT4PsJYGw=",
    // Source URL: https://www.amazontrust.com/repository/AmazonRootCA3.cer
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=Amazon Root CA 3,O=Amazon,C=US
    // Issuer: CN=Amazon Root CA 3,O=Amazon,C=US
    // Expiration Date: 2040-05-26 00:00:00
    // Serial Number: 66C9FD5749736663F3B0B9AD9E89E7603F24A
    // SHA256 Fingerprint: 18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4
    "sha256/MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKlui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6jQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSrttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkrBqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteMYyRIHN8wfdVoOw==",
    // Source URL: https://www.amazontrust.com/repository/AmazonRootCA4.cer
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=Amazon Root CA 4,O=Amazon,C=US
    // Issuer: CN=Amazon Root CA 4,O=Amazon,C=US
    // Expiration Date: 2040-05-26 00:00:00
    // Serial Number: 66C9FD7C1BB104C2943E5717B7B2CC81AC10E
    // SHA256 Fingerprint: e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092
    "sha256/MIIB8jCCAXigAwIBAgITBmyf18G7EEwpQ+Vxe3ssyBrBDjAKBggqhkjOPQQDAzA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSA0MB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZLY7Bi9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri83BkM6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFNPsxzplbszh2naaVvuc84ZtV+WBMAoGCCqGSM49BAMDA2gAMGUCMDqLIfG9fhGt0O9Yli/W651+kI0rz2ZVwyzjKKlwCkcO8DdZEv8tmZQoTipPNU0zWgIxAOp1AE47xDqUEpHJWEadIRNyp4iciuRMStuW1KyLa2tJElMzrdfkviT8tQp21KW8EA==",
    // Source URL: https://www.amazontrust.com/repository/SFSRootCAG2.cer
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=Starfield Services Root Certificate Authority - G2,O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
    // Issuer: CN=Starfield Services Root Certificate Authority - G2,O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
    // Expiration Date: 2037-12-31 23:59:59
    // Serial Number: 0
    // SHA256 Fingerprint: 568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5
    "sha256/MIID7zCCAtegAwIBAgIBADANBgkqhkiG9w0BAQsFADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xOzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgZgxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTswOQYDVQQDEzJTdGFyZmllbGQgU2VydmljZXMgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANUMOsQq+U7i9b4Zl1+OiFOxHz/Lz58gE20pOsgPfTz3a3Y4Y9k2YKibXlwAgLIvWX/2h/klQ4bnaRtSmpDhcePYLQ1Ob/bISdm28xpWriu2dBTrz/sm4xq6HZYuajtYlIlHVv8loJNwU4PahHQUw2eeBGg6345AWh1KTs9DkTvnVtYAcMtS7nt9rjrnvDH5RfbCYM8TWQIrgMw0R9+53pBlbQLPLJGmpufehRhJfGZOozptqbXuNC66DQO4M99H67FrjSXZm86B0UVGMpZwh94CDklDhbZsc7tk6mFBrMnUVN+HL8cisibMn1lUaJ/8viovxFUcdUBgF4UCVTmLfwUCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJxfAN+qAdcwKziIorhtSpzyEZGDMA0GCSqGSIb3DQEBCwUAA4IBAQBLNqaEd2ndOxmfZyMIbw5hyf2E3F/YNoHN2BtBLZ9g3ccaaNnRbobhiCPPE95Dz+I0swSdHynVv/heyNXBve6SbzJ08pGCL72CQnqtKrcgfU28elUSwhXqvfdqlS5sdJ/PHLTyxQGjhdByPq1zqwubdQxtRbeOlKyWN7Wg0I8VRw7j6IPdj/3vQQF3zCepYoUz8jcI73HPdwbeyBkdiEDPfUYd/x7H4c7/I9vG+o1VTqkC50cRRj70/b17KSa7qWFiNyi2LSr2EIZkyXCn0q23KXB56jzaYyWf/Wi3MOxw+3WKt21gZ7IeyLnp2KhvAotnDU0mV3HaIPzBSlCNsSi6",
    // Source URL: https://cacerts.digicert.com/DigiCertHighAssuranceEVRootCA.crt
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
    // Issuer: CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
    // Expiration Date: 2031-11-10 00:00:00
    // Serial Number: 2AC5C266A0B409B8F0B79F2AE462577
    // SHA256 Fingerprint: 7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
    "sha256/MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgRVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTWPNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEMxChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFBIk5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsgEsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3NecnzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6zeM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jFhS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCevEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep+OkuE6N36B9K",
    // Source URL: https://cacerts.digicert.com/DigiCertTLSECCP384RootG5.crt
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
    // Issuer: CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
    // Expiration Date: 2046-01-14 23:59:59
    // Serial Number: 9E09365ACF7D9C8B93E1C0B042A2EF3
    // SHA256 Fingerprint: 018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05
    "sha256/MIICGTCCAZ+gAwIBAgIQCeCTZaz32ci5PhwLBCou8zAKBggqhkjOPQQDAzBOMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJjAkBgNVBAMTHURpZ2lDZXJ0IFRMUyBFQ0MgUDM4NCBSb290IEc1MB4XDTIxMDExNTAwMDAwMFoXDTQ2MDExNDIzNTk1OVowTjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSYwJAYDVQQDEx1EaWdpQ2VydCBUTFMgRUNDIFAzODQgUm9vdCBHNTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMFEoc8Rl1Ca3iOCNQfN0MsYndLxf3c1TzvdlHJS7cI7+Oz6e2tYIOyZrsn8aLN1udsJ7MgT9U7GCh1mMEy7H0cKPGEQQil8pQgO4CLp0zVozptjn4S1mU1YoI71VOeVyaNCMEAwHQYDVR0OBBYEFMFRRVBZqz7nLFr6ICISB4CIfBFqMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMDA2gAMGUCMQCJao1H5+z8blUD2WdsJk6Dxv3J+ysTvLd6jLRl0mlpYxNjOyZQLgGheQaRnUi/wr4CMEfDFXuxoJGZSZOoPHzoRgaLLPIxAJSdYsiJvRmEFOml+wG4DXZDjC5Ty3zfDBeWUA==",
    // Source URL: https://cacerts.digicert.com/DigiCertTLSRSA4096RootG5.crt
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=DigiCert TLS RSA4096 Root G5,O=DigiCert\, Inc.,C=US
    // Issuer: CN=DigiCert TLS RSA4096 Root G5,O=DigiCert\, Inc.,C=US
    // Expiration Date: 2046-01-14 23:59:59
    // Serial Number: 8F9B478A8FA7EDA6A333789DE7CCF8A
    // SHA256 Fingerprint: 371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75
    "sha256/MIIFZjCCA06gAwIBAgIQCPm0eKj6ftpqMzeJ3nzPijANBgkqhkiG9w0BAQwFADBNMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJTAjBgNVBAMTHERpZ2lDZXJ0IFRMUyBSU0E0MDk2IFJvb3QgRzUwHhcNMjEwMTE1MDAwMDAwWhcNNDYwMTE0MjM1OTU5WjBNMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJTAjBgNVBAMTHERpZ2lDZXJ0IFRMUyBSU0E0MDk2IFJvb3QgRzUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCz0PTJeRGd/fxmgefM1eS87IE+ajWOLrfn3q/5B03PMJ3qCQuZvWxX2hhKuHisOjmopkisLnLlvevxGs3npAOpPxG02C+JFvuUAT27L/gTBaF4HI4o4EXgg/RZG5Wzrn4DReW+wkL+7vI8toUTmDKdFqgpwgscONyfMXdcvyej/Cestyu9dJsXLfKB2l2w4SMXPohKEiPQ6s+d3gMXsUJKoBZMpG2T6T867jp8nVid9E6P/DsjyG244gXazOvswzH016cpVIDPRFtMbzCe88zdH5RDnU1/cHAN1DrRN/BsnZvAFJNY781BOHW8EwOVfH/jXOnVDdXifBBiqmvwPXbzP6PosMH976pXTayGpxi0KcEsDr9kvimM2AItzVwv8n/vFfQMFawKsPHTDU9qTXeXAaDxZre3zu/O7Oyldcqs4+Fj97ihBMi8ez9dLRYiVu1ISf6nL3kwJZu6ay0/nTvEF+cdLvvyz6b84xQslpghjLSR6Rlgg/IwKwZzUNWYOwbpx4oMYIwo+FKbbuH2TbsGJJvXKyY//SovcfXWJL5/MZ4PbeiPT02jP/816t9JXkGPhvnxd3lLG7SjXi/7RgLQZhNeXoVPzthwiHvOAbWWl9fNff2C+MIkwcoBOU+NosEUQB+cZtUMCUbW8tDRSHZWOkPLtgoRObqME2wGtZ7P6wIDAQABo0IwQDAdBgNVHQ4EFgQUUTMc7TZArxfTJc1paPKvTiM+s0EwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAGCmr1tfV9qJ20tQqcQjNSH/0GEwhJG3PxDPJY7Jv0Y02cEhJhxwGXIeo8mH/qlDZJY6yFMECrZBu8RHANmfGBg7sg7zNOok992vIGCukihfNudd5N7HPNtQOa27PShNlnx2xlv0wdsUpasZYgcYQF+Xkdycx6u1UQ3maVNVzDl92sURVXLFO4uJ+DQtpBflF+aZfTCIITfNMBc9uPK8qHWgQ9w+iUuQrm0D4ByjoJYJu32jtyoQREtGBzRj7TG5BO6jm5qu5jF49OokYTurWGT/u4cnYiWB39yhL/btp/96j1EuMPikAdKFOV8BmZZvWltwGUb+hmA+rYAQCd05JS9Yf7vSdPD3Rh9GOUrYU9DzLjtxpdRv/PNn5AeP3SYZ4Y1b+qOTEZvpyDrDVWiakuFSdjjo4bq9+0/V77PnSIMx8IIh47a+p6tv75/fTM8BuGJqIz3nCU2AG3swpMPdB380vqQmsvZB6Akd4yCYqjdP//fx4ilwMUc/dNAUFvohigLVigmUdy7yWSiLfFCSCmZ4OIN1xLVaqBHG5cGdZlXPU8Sv13WFqUITVuwhd4GTWgzqltlJyqEI8pc7bZsEGCREjnwB8twl2F6GmrE52/WRMmrRpnCKovfepEWFJqgejF0pW8hL2JpqA15w8oVPbEtoL8pU9ozaMv7Da4M/OMZ+",
    // Source URL: https://secure.globalsign.com/cacert/rootr46.crt
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE
    // Issuer: CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE
    // Expiration Date: 2046-03-20 00:00:00
    // Serial Number: 11D2BBB9D723189E405F0A9D2DD0DF2567D1
    // SHA256 Fingerprint: 4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9
    "sha256/MIIFWjCCA0KgAwIBAgISEdK7udcjGJ5AXwqdLdDfJWfRMA0GCSqGSIb3DQEBDAUAMEYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGgYDVQQDExNHbG9iYWxTaWduIFJvb3QgUjQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2MDMyMDAwMDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExHDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCsrHQy6LNl5brtQyYdpokNRbopiLKkHWPd08EsCVeJOaFV6Wc0dwxu5FUdUiXSE2te4R2pt32JMl8Nnp8semNgQB+msLZ4j5lUlghYruQGvGIFAha/r6gjA7aUD7xubMLL1aa7DOn2wQL7Id5m3RerdELv8HQvJfTqa1VbkNud316HCkD7rRlr+/fKYIje2sGP1q7Vf9Q8g+7XFkyDRTNrJ9CG0Bwta/OrffGFqfUo0q3v84RLHIf8E6M6cqJaESvWJ3En7YEtbWaBkoe0G1h6zD8K+kZPTXhc+CtI4wSEy132tGqzZfxCnlEmIyDLPRT5ge1lFgBPGmSXZgjPjHvjK8Cd+RTyG/FWaha/LIWFzXg4mutCagI0GIMXTpRW+LaCtfOW3T3zvn8gdz57GSNrLNRyc0NXfeD412lPFzYE+cCQYDdF3uYM2HSNrpyibXRdQr4G9dlkbgIQrImwTDsHTUB+JMWKmIJ5jqSngiCNI/onccnfxkF0oE32kRbcRoxfKWMxWXEM2G/CtjJ9++ZdU6Z+Ffy7dXxd7Pj2Fxzsx2sZy/N78CsHpdlseVR2bJ0cpm4O6XkMqCNqo98bMDGfsVR7/mrLZqrcZdCinkqaByFrgY/bxFn63iLABJzjqls2k+g9vXqhnQt2sQvHnf3PmKgGwvgqo6GDoLclcqUC4wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA1yrc4GHqMywptWU4jaWSf8FmSwwDQYJKoZIhvcNAQEMBQADggIBAHx47PYCLLtbfpIrXTncvtgdokIzTfnvpCo7RGkerNlFo048p9gkUbJUHJNOxO97k4VgJuoJSOD1u8fpaNK7ajFxzHmuEajwmf3lH7wvqMxX63bEIaZHU1VNaL8FpO7XJqti2kM3S+LGteWygxk6x9PbTZ4IevPuzz5i+6zoYMzRx6Fcg0XERczzF2sUyQQCPtIkpnnpHs6i58FZFZ8d4kuaPp92CC1r2LpXFNqD6v6MVenQTqnMdzGxRBF6XLE+0xRFFRhiJBPSy03OXIPBNvIQtQ6IbbjhVp+J3pZmOUdkLG5NrmJ7v2B0GbhWrJKsFjLtrWhV/pi60zTe9Mlhww6G9kuEYO4Ne7UyWHmRVSyBQ7N0H3qqJZ4d16GLuc1CLgSkZoNNiTW2bKg2SnkheCLQQrzRQDGQob4Ez8pn7fXwgNNgyYMqIgXQBztSvwyeqiv5u+YfjyW6hY0XHgL+XVAEV8/+LbzvXMAaq7afJMbfc2hIkCwU9D9SGuTSyxTDYWnP4vkYxboznxSjBF25cfe1lNj2M8FawTSLfJvdkzrnE6JwYZ+vj+vYxXX4M2bUdGc6N3ec592kD3ZDZopD8p/7DEJ4Y9HiD2971KE9dJeFt0g5QdYg/NA6s/rob8SKunE3vouXsXgxT7PntgMTzlSdriVZzH81Xwj3QEUxeCp6",
    // Source URL: https://secure.globalsign.com/cacert/roote46.crt
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=GlobalSign Root E46,O=GlobalSign nv-sa,C=BE
    // Issuer: CN=GlobalSign Root E46,O=GlobalSign nv-sa,C=BE
    // Expiration Date: 2046-03-20 00:00:00
    // Serial Number: 11D2BBBA336ED4BCE62468C50D841D98E843
    // SHA256 Fingerprint: cbb9c44d84b8043e1050ea31a69f514955d7bfd2e2c6b49301019ad61d9f5058
    "sha256/MIICCzCCAZGgAwIBAgISEdK7ujNu1LzmJGjFDYQdmOhDMAoGCCqGSM49BAMDMEYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGgYDVQQDExNHbG9iYWxTaWduIFJvb3QgRTQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2MDMyMDAwMDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExHDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAScDrHPt+ieUnd1NPqlRqetMhkytAepJ8qUuwzSChDH2omwlwxwEwkBjtjqR+q+soArzfwoDdusvKSGN+1wCAB16pMLey5SnCNoIwZD7JIvU4Tb+0cUB+hflGddyXqBPCCjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQxCpCPtsad0kRLgLWi5h+xEk8blTAKBggqhkjOPQQDAwNoADBlAjEA31SQ7Zvvi5QCkxeCmb6zniz2C5GMn0oUsfZkvLtoURMMA/cVi4RguYv/Uo7njLwcAjA8+RHUjE7AwWHCFUyqqx0LMV87HOIAl0Qx5v5zli/altP+CAezNIm8BZ/3Hobui3A=",
    // Source URL: https://i.pki.goog/r2.crt
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=GTS Root R2,O=Google Trust Services LLC,C=US
    // Issuer: CN=GTS Root R2,O=Google Trust Services LLC,C=US
    // Expiration Date: 2036-06-22 00:00:00
    // Serial Number: 203E5AEC58D04251AAB1125AA
    // SHA256 Fingerprint: 8d25cd97229dbf70356bda4eb3cc734031e24cf00fafcfd32dc76eb5841c7ea8
    "sha256/MIIFVzCCAz+gAwIBAgINAgPlrsWNBCUaqxElqjANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjIwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDO3v2m++zsFDQ8BwZabFn3GTXd98GdVarTzTukk3LvCvptnfbwhYBboUhSnznFt+4orO/LdmgUud+tAWyZH8QiHZ/+cnfgLFuv5AS/T3KgGjSY6Dlo7JUle3ah5mm5hRm9iYz+re026nO8/4Piy33B0s5Ks40FnotJk9/BW9BuXvAuMC6C/Pq8tBcKSOWIm8Wba96wyrQD8Nr0kLhlZPdcTK3ofmZemde4wj7I0BOdre7kRXuJVfeKH2JShBKzwkCX44ofR5GmdFrS+LFjKBC4swm4VndAoiaYecb+3yXuPuWgf9RhD1FLPD+M2uFwdNjCaKH5wQzpoeJ/u1U8dgbuak7MkogwTZq9TwtImoS1mKPV+3PBV2HdKFZ1E66HjucMUQkQdYhMvI35ezzUIkgfKtzra7tEscszcTJGr61K8YzodDqs5xoic4DSMPclQsciOzsSrZYuxsN2B6ogtzVJV+mSSeh2FnIxZyuWfoqjx5RWIr9qS34BIbIjMt/kmkRtWVtd9QCgHJvGeJeNkP+byKq0rxFROV7Z+2et1VsRnTKaG73VululycslaVNVJ1zgyjbLiGH7HrfQy+4W+9OmTN6SpdTi3/UGVN4unUu0kzCqgc7dGtxRcw1PcOnlthYhGXmy5okLdWTK1au8CcEYof/UVKGFPP0UJAOyh9OktwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUu//KjiOfT5nK2+JopqUVJxce2Q4wDQYJKoZIhvcNAQEMBQADggIBAB/Kzt3HvqGf2SdMC9wXmBFqiN495nFWcrKeGk6c1SuYJF2ba3uwM4IJvd8lRuqYnrYb/oM80mJhwQTtzuDFycgTE1XnqGOtjHsB/ncw4c5omwX4Eu55MaBBRTUoCnGkJE+M3DyCB19m3H0Q/gxhswWV7uGugQ+o+MePTagjAiZrHYNSVc61LwDKgEDg4XSsYPWHgJ2uNmSRXbBoGOqKYcl3qJfEycel/FVL8/B/uWU9J2jQzGv6U53hkRrJXRqWbTKH7QMgyALOWr7Z6v2yTcQvG99fevX4i8buMTolUVVnjWQye+mew4K6Ki3pHrTgSAai/GevHyICc/sgCq+dVEuhzf9gR7A/Xe8bVr2XIZYtCtFenTgCR2y59PYjJbigapordwj6xLEokCZYCDzifqrXPW+6MYgKBesntaFJ7qBFVHvmJ2WZICGoo7z7GJa7Um8M7YNRTOlZ4iBgxcJlkoKM8xAfDoqXvneCbT+PHV28SSe9zE8P4c52hgQjxcCMElv924SgJPFI/2R80L5cFtHvma3AH/vLrrw4IgYmZNralw4/KBVEqE8AyvCazM90arQ+POuV7LXTWtiBmelDGDfrs7vRWGJB82bSj6p4lVQgw1oudCvV0b4YacCs1aTPObpRhANl6WLAYv7YTVWW4tAR+kg0Eeye7QUd5MjWHYbL",
    // Source URL: https://i.pki.goog/r4.crt
    // Certificate #1 Details:
    // Original Format: DER
    // Subject: CN=GTS Root R4,O=Google Trust Services LLC,C=US
    // Issuer: CN=GTS Root R4,O=Google Trust Services LLC,C=US
    // Expiration Date: 2036-06-22 00:00:00
    // Serial Number: 203E5C068EF631A9C72905052
    // SHA256 Fingerprint: 349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d
    "sha256/MIICCTCCAY6gAwIBAgINAgPlwGjvYxqccpBQUjAKBggqhkjOPQQDAzBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa6zzuhXyiQHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvRHYqjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSATNbrdP9JNqPV2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNpADBmAjEA6ED/g94D9J+uHXqnLrmvT/aDHQ4thQEd0dlq7A/Cr8deVl5c1RxYIigL9zC2L7F8AjEA8GE8p/SgguMh1YQdc4acLa/KNJvxn7kjNuK8YAOdgLOaVsjh4rsUecrNIdSUtUlD",
    // Source URL: https://www.identrust.com/file-download/download/public/5718
    // Certificate #1 Details:
    // Original Format: PKCS7-DER
    // Subject: CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US
    // Issuer: CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US
    // Expiration Date: 2034-01-16 18:12:23
    // Serial Number: A0142800000014523C844B500000002
    // SHA256 Fingerprint: 5d56499be4d2e08bcfcad08a3e38723d50503bde706948e42f55603019e528ae
    "sha256/MIIFYDCCA0igAwIBAgIQCgFCgAAAAUUjyES1AAAAAjANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MScwJQYDVQQDEx5JZGVuVHJ1c3QgQ29tbWVyY2lhbCBSb290IENBIDEwHhcNMTQwMTE2MTgxMjIzWhcNMzQwMTE2MTgxMjIzWjBKMQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MScwJQYDVQQDEx5JZGVuVHJ1c3QgQ29tbWVyY2lhbCBSb290IENBIDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCnUBneP5k91DNG8W9RYYKyqU+PZ4ldhNlT3Qwo2dfw/66VQ3KZ+bVdfIrBQuExUHTRgQ18zZshq0PirK1ehm7zCYofWjK9ouuU+ehcCuz/mNKvcbO0U59Oh++SvL3sTzIwiEsXXlfEU8L2ApeN2WIrvyQfYo3fw7gpS0l4PJNgiCL8mdo2yMKi1CxUAGc1bnO/AljwpN3lsKImesrgNqUZFvX9t++uP0D1bVoE/c40yiTcdCMbXTMTEl3EASX2MN0CXZ/g1Ue9tOsbobtJSdifWwLziuQkkORiT0/Br4sOdBeo0XKIanoBScy0RnnGF7HamB4HWfp1IYVl3ZBWzvurpWCdxJ35UrCLvYf5jysjCiN2O/cz4ckA82n5S6LgTrx+kzmEB/dEcH7+B1rlsazRGMzyNeVJSQjKVsk9+w8YfYs7wRPCTY/JTw436R+hDmrfYi7LNQZReSzIJTj0+kuniVyc0uMNOYZKdHzVWYfCP04MXFL0PfdSgvHqo6z9STQaKPNBiDoT7uje/5kdX7rL6B7yuVBgwDHTc+XvvqDtMwt0viAgxGds8AgDelWAf0ZOlqf0Hj7h9tgJ4TNkK2PXMl6f+cB7D3hvl7yTmvmcEpB4eoCHFddydJxVdHixuuFucAS6T6C6aMN7/zHwcz09lCqxC0EOoP5NiGVreTO01wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7UQZwNPwBovupHu+QucmVMiONnYwDQYJKoZIhvcNAQELBQADggIBAA2ukDL2pkt8RHYZYR4nKM1eVO8lvOMIkPkp165oCOGUAFjvLi5+U1KMtlwH6oi6mYtQlNeCgN9hCQCTrQ0U5s7B8jeUeLBfnLOic7iPBZM4zY0+sLj7wM+x8uwtLRvM7Kqas6pgghstO8OEPVeKlh6cdbjTMM1gCIOQ045U8U1mwF10A0Cj7oV+wh93nAbowacYXVKV7cndJZ5t+qntozo00Fl72u1Q8zW/7esUTTHHYPTa8Yec4kjixsU3+wYQ+nVZZjFHKdp2mhzpgq7vmrlR94gjmmmVYjzlVYA211QC//G5Xc7UI2/YRYRKW2XviQzdFKcgyxilJbQN+QHwotL0AMh0jqEqSI5l2xPE4iUXfeu+h1sXIFRRk0pTAwvsXcoz7WL9RccvW9xYoIA55vrX/hMUpu09lEpCdNTDd1lzzY9GvlU47/rokTLql1gEIt44w8y8bckzOmoKaT+gyOpyj4xjhiO9bTyWnpXgSUyqorkqG5w2gXjtw+hG4iZZRHUe2XWJUc0QhJ1hYMtd+ZciTY6Y5uN/9lu7rs3KSoFrXgvzUeF0K+l+J6fZmUlO+KWA2yUPHGNiiskzZ2s8EIPGrd6ozRaOjfAHN3Gf8qv8QfXBi+wAN10J5U6A7/qxXDgGpRtK4dw4LTzcqx+QGtVKnO7RcGzM7vRX+Bi6hG6H",
    // Source URL: https://www.identrust.com/file-download/download/public/5842
    // Certificate #1 Details:
    // Original Format: PKCS7-PEM
    // Subject: CN=IdenTrust Commercial Root TLS ECC CA 2,O=IdenTrust,C=US
    // Issuer: CN=IdenTrust Commercial Root TLS ECC CA 2,O=IdenTrust,C=US
    // Expiration Date: 2039-04-11 21:11:10
    // Serial Number: 40018ECF000DE911D7447B73E4C1F82E
    // SHA256 Fingerprint: 983d826ba9c87f653ff9e8384c5413e1d59acf19ddc9c98cecae5fdea2ac229c
    "sha256/MIICbDCCAc2gAwIBAgIQQAGOzwAN6RHXRHtz5MH4LjAKBggqhkjOPQQDBDBSMQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MS8wLQYDVQQDEyZJZGVuVHJ1c3QgQ29tbWVyY2lhbCBSb290IFRMUyBFQ0MgQ0EgMjAeFw0yNDA0MTEyMTExMTFaFw0zOTA0MTEyMTExMTBaMFIxCzAJBgNVBAYTAlVTMRIwEAYDVQQKEwlJZGVuVHJ1c3QxLzAtBgNVBAMTJklkZW5UcnVzdCBDb21tZXJjaWFsIFJvb3QgVExTIEVDQyBDQSAyMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBwomiZTgLg8KqEImMmnO5rNPbOo9sv5w4nJh45CXs9Gcu8YET9ulxsyVBCVSfSYeppdtXFEWYyBi0QRCAlp5YZHQBH675v5rWVKRXvhzsuUNi9Xw0Zy1bAXaikmsrY/J0L52j2RulW4q4WvE7f23VFwZud82J8k0YG+M4MpmdOho1rsKjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQhNGgGrnXhVx/FuQqjXpuH+IlbwzAKBggqhkjOPQQDBAOBjAAwgYgCQgDc9F4WOxAgci2uQWfsX9cjeIvDXaaeVjDz31Ycc+ZdPrK1JKrBf6CuTwWy8VojtGxdM3PJMkJC4LGPuhcvkHLo4gJCAV5h+PXe4bDJ3QxE8hkGFoUWAk6KtMCIpbLyt5pHrROi+YW9MpScoNGJkg96G1ETvJTWz6dv0uQYjKXt3jlOfQ7g",
    // Source URL: https://ssl-ccp.secureserver.net/repository/sfroot-g2.crt
    // Certificate #1 Details:
    // Original Format: PEM
    // Subject: CN=Starfield Root Certificate Authority - G2,O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
    // Issuer: CN=Starfield Root Certificate Authority - G2,O=Starfield Technologies\, Inc.,L=Scottsdale,ST=Arizona,C=US
    // Expiration Date: 2037-12-31 23:59:59
    // Serial Number: 0
    // SHA256 Fingerprint: 2ce1cb0bf9d2f9e102993fbe215152c3b2dd0cabde1c68e5319b839154dbb7f5
    "sha256/MIID3TCCAsWgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBjzELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xMjAwBgNVBAMTKVN0YXJmaWVsZCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIzNTk1OVowgY8xCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIwMAYDVQQDEylTdGFyZmllbGQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3twQP89o/8ArFvW59I2Z154qK3A2FWGMNHttfKPTUuiUP3oWmb3ooa/RMgnLRJdzIpVv257IzdIvpy3Cdhl+72WoTsbhm5iSzchFvVdPtrX8WJpRBSiUZV9Lh1HOZ/5FSuS/hVclcCGfgXcVnrHigHdMWdSL5stPSksPNkN3mSwOxGXn/hbVNMYq/NHwtjuzqd+/x5AJhhdM8mgkBj87JyahkNmcrUDnXMN/uLicFZ8WJ/X7NfZTD4p7dNdloedl40wOiWVpmKs/B/pM293DIxfJHP4F8R+GuqSVzRmZTRouNjWwl2tVZi4Ut0HZbUJtQIBFnQmA4O5t78w+wfkPECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHwMMh+n2TB/xH1oo2Kooc6rB1snMA0GCSqGSIb3DQEBCwUAA4IBAQARWfolTwNvlJk7mh+ChTnUdgWUXuEok21iXQnCoKjUsHU48TRqneSfioYmUeYs0cYtbpUgSpIB7LiKZ3sx4mcujJUDJi5DnUox9g61DLu34jd/IroAow57UvtruzvE03lRTs2Q9GcHGcg8RnoNAX3FWOdt5oUwF5okxBDgBPfg8n/Uqgr/Qh037ZTlZFkSIHc40zI+OIF1lnP6aI+xy84fxez6nH7PfrHxBy22/L/KpL/QlwVKvOoYKAKQvVR4CSFx09F9HdkWsKlhPdAKACL8x3vLCWRFCztAgfd9fDL1mMpYjn0q7pBZc2T5NnReJaH1ZgUufzkVqSr7UIuOhWn0"
    };

    /**
     * Builder.
     *
     * @param clientId This value is the client id provided by Duo in the admin panel.
     * @param clientSecret This value is the client secret provided by Duo in the admin panel.
     * @param apiHost This value is the api host provided by Duo in the admin panel.
     * @param redirectUri This value is the uri which Duo should redirect to after 2FA is completed.
     */
    public Builder(String clientId, String clientSecret, String apiHost,
                   String redirectUri) {
      this.clientId = clientId;
      this.clientSecret = clientSecret;
      this.apiHost = apiHost;
      this.redirectUri = redirectUri;
      this.caCerts = DEFAULT_CA_CERTS;
      this.useDuoCodeAttribute = true;
      this.userAgent = computeUserAgent();
    }

    /**
     * Builder.
     *
     * @param clientId     This value is the client id provided by Duo in the admin
     *                     panel.
     * @param clientSecret This value is the client secret provided by Duo in the
     *                     admin panel.
     * @param proxyHost    This value is the hostname of the proxy server
     * @param proxyPort    This value is the port number of the proxy server
     * @param apiHost      This value is the api host provided by Duo in the admin
     *                     panel.
     * @param redirectUri  This value is the uri which Duo should redirect to after
     *                     2FA is completed.
     */
    public Builder(String clientId, String clientSecret, String proxyHost,
                   Integer proxyPort, String apiHost, String redirectUri) {
      this.clientId = clientId;
      this.clientSecret = clientSecret;
      this.apiHost = apiHost;
      this.proxyHost = proxyHost;
      this.proxyPort = proxyPort;
      this.redirectUri = redirectUri;
      this.caCerts = DEFAULT_CA_CERTS;
      this.useDuoCodeAttribute = true;
      this.userAgent = computeUserAgent();
    }

    /**
     * Build the client object.
     *
     * @return {@link Client}
     *
     * @throws DuoException For problems building the client
     */
    public Client build() throws DuoException {
      validateClientParams(clientId, clientSecret, apiHost, redirectUri);

      Client client = new Client();
      client.clientId = clientId;
      client.clientSecret = clientSecret;
      client.apiHost = apiHost;
      client.redirectUri = redirectUri;
      client.useDuoCodeAttribute = useDuoCodeAttribute;
      client.userAgent = userAgent;
      client.duoConnector = new DuoConnector(apiHost, proxyHost, proxyPort, caCerts);

      return client;
    }

    /**
     * Optionally use custom CA Certificates when validating connections to Duo.
     *
     * @param userCaCerts List of CA Certificates to use
     * 
     * @return the Builder
     */
    public Builder setCACerts(String[] userCaCerts) {
      if (validateCaCert(userCaCerts)) {
        this.caCerts = userCaCerts;
      }
      return this;
    }

    /**
     * Optionally toggle the returned authorization parameter to use duo_code vs code.
     * Defaults true to use duo_code.
     *
     * @param useDuoCodeAttribute true/false toggle
     * 
     * @return the Builder
     */
    public Builder setUseDuoCodeAttribute(boolean useDuoCodeAttribute) {
      this.useDuoCodeAttribute = useDuoCodeAttribute;
      return this;
    }

    /**
     * Optionally appends string to userAgent.
     *
     * @param newUserAgent Additional info that will be added to the end of the user agent string
     * 
     * @return the Builder
     */
    public Builder appendUserAgentInfo(String newUserAgent) {
      userAgent = format("%s %s", userAgent, newUserAgent);
      return this;
    }

    private String computeUserAgent() {
      String duoAgent = format("%s/%s", USER_AGENT_LIB, USER_AGENT_VERSION);
      String javaAgent = format("%s/%s",
              System.getProperty("java.vendor"),
              System.getProperty("java.version"));
      String osAgent = format("%s/%s/%s",
              System.getProperty("os.name"),
              System.getProperty("os.version"),
              System.getProperty("os.arch"));

      return format("%s %s %s", duoAgent, javaAgent, osAgent);
    }
  }

  // **************************************************
  // Public methods
  // **************************************************
  /**
   * Checks if Duo is healthy and available for 2FA.
   *
   * @return {@link HealthCheckResponse}
   *
   * @throws DuoException For health check errors
   */
  public HealthCheckResponse healthCheck() throws DuoException {
    String aud = getAndValidateUrl(apiHost, OAUTH_V_1_HEALTH_CHECK_ENDPOINT).toString();
    HealthCheckResponse response = duoConnector.duoHealthcheck(clientId,
                createJwt(clientId, clientSecret, aud));
    if (!response.wasSuccess()) {
      throw new DuoException(response.getMessage());
    }
    return response;
  }


  /**
   * Constructs a string which can be used to redirect the client browser to Duo for 2FA.
   *
   * @param username The user to be authenticated by Duo.
   * @param state A randomly generated String with at least 22 characters
   *              This value will be returned to the integration post 2FA
   *              and should be validated. {@link #generateState} exists as a utility function to
   *              generate this param.
   * @return String
   *
   * @throws DuoException For problems creating the auth url
   */
  public String createAuthUrl(String username, String state) throws DuoException {
    validateUsername(username);
    validateState(state);
    String request = createJwtForAuthUrl(clientId, clientSecret, redirectUri,
            state, username, useDuoCodeAttribute);
    String query = format(
            "?scope=openid&response_type=code&redirect_uri=%s&client_id=%s&request=%s",
            redirectUri, clientId, request);
    return getAndValidateUrl(apiHost, OAUTH_V_1_AUTHORIZE_ENDPOINT + query).toString();
  }


  /**
   * Verifies the duoCode returned by Duo and exchanges it for a {@link Token} which contains
   * information pertaining to the auth.  Uses the default token validator defined in
   * DuoIdTokenValidator.
   * To use a custom validator, see exchangeAuthorizationCodeFor2FAResult(String, TokenValidator)
   *
   * @param duoCode This string is an identifier for the auth and should be exchanged with Duo for a
   *             token to determine if the auth was successful as well as obtain meta-data about
   *             about the auth.
   *
   * @param username The user to be authenticated by Duo
   *
   * @return {@link Token}
   *
   * @throws DuoException For errors exchanging duoCode for 2FA results
   */
  public Token exchangeAuthorizationCodeFor2FAResult(String duoCode, String username)
      throws DuoException {
    TokenValidator validator = new DuoIdTokenValidator(clientSecret, username, clientId, apiHost);
    return exchangeAuthorizationCodeFor2FAResult(duoCode, validator);
  }

  /**
   * Verifies the duoCode returned by Duo and exchanges it for a {@link Token} which contains
   * information pertaining to the auth.  This version of the method allows the use of a
   * custom JWT token validator.
   * If you use a custom validator:
   *   You MUST confirm the integrity of the token by using the client secret to validate the
   *   SHA512 HMAC
   *   You MUST check the claims for
   *     Issuer
   *     Audience
   *     Issued at / Expiration
   *     Username (preferred_username)
   *
   * @param duoCode This string is an identifier for the auth and should be exchanged with Duo for a
   *                token to determine if the auth was successful as well as obtain meta-data about
   *                the auth.
   *
   * @param validator A TokenValidator that will validate and decode the JWT ID Token provided
   *                  by Duo.
   *
   * @return {@link Token}
   *
   * @throws DuoException For errors exchanging duoCode for 2FA results
   *
   */
  public Token exchangeAuthorizationCodeFor2FAResult(String duoCode, TokenValidator validator)
      throws DuoException {
    String aud = getAndValidateUrl(apiHost, OAUTH_V_1_TOKEN_ENDPOINT).toString();
    TokenResponse response = duoConnector.exchangeAuthorizationCodeFor2FAResult(userAgent,
            "authorization_code", duoCode, redirectUri, CLIENT_ASSERTION_TYPE,
            createJwt(clientId, clientSecret, aud));
    String idToken = response.getId_token();
    DecodedJWT decodedJwt = validator.validateAndDecode(idToken);
    return transformDecodedJwtToToken(decodedJwt);
  }

  /**
   * Generates a 36 character random identifier to be used as the state variable in the
   * createAuthUrl method.  This value should be stored in a variable and validated against
   * the state returned by Duo.
   *
   * @return String
   */
  public String generateState() {
    return Utils.generateJwtId(36);
  }

}
