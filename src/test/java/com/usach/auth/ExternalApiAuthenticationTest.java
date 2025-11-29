//package com.usach.auth;
//
//import org.dspace.core.Context;
//import org.dspace.eperson.EPerson;
//import org.dspace.eperson.Group;
//import org.dspace.eperson.factory.EPersonServiceFactory;
//import org.dspace.eperson.service.EPersonService;
//import org.dspace.eperson.service.GroupService;
//import org.dspace.services.ConfigurationService;
//import org.dspace.services.factory.DSpaceServicesFactory;
//import org.junit.jupiter.api.*;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.InOrder;
//import org.mockito.MockedStatic;
//import org.mockito.junit.jupiter.MockitoExtension;
//
//import javax.servlet.http.HttpServletRequest;
//import java.net.http.HttpClient;
//import java.net.http.HttpRequest;
//import java.net.http.HttpResponse;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.mockito.ArgumentMatchers.*;
//import static org.mockito.Mockito.*;
//
//@ExtendWith(MockitoExtension.class)
//class ExternalApiAuthenticationTest {
//
//    @org.mockito.Mock Context context;
//    @org.mockito.Mock HttpServletRequest httpReq;
//
//    @org.mockito.Mock ConfigurationService configurationService;
//    @org.mockito.Mock EPersonService ePersonService;
//    @org.mockito.Mock GroupService groupService;
//    @org.mockito.Mock EPerson eperson;
//    @org.mockito.Mock Group group;
//
//    @org.mockito.Mock HttpClient httpClient;
//    @org.mockito.Mock HttpClient.Builder httpClientBuilder;
//    @org.mockito.Mock HttpResponse<String> httpResponse;
//
//    MockedStatic<DSpaceServicesFactory> dspaceFactoryMock;
//    MockedStatic<EPersonServiceFactory> ePersonFactoryMock;
//    MockedStatic<HttpClient> httpClientStaticMock;
//
//    ExternalApiAuthentication auth;
//
//    @BeforeEach
//    void setUp() {
//        // Mock estático de DSpaceServicesFactory
//        dspaceFactoryMock = mockStatic(DSpaceServicesFactory.class);
//        DSpaceServicesFactory dspaceServicesFactory = mock(DSpaceServicesFactory.class);
//        dspaceFactoryMock.when(DSpaceServicesFactory::getInstance).thenReturn(dspaceServicesFactory);
//        when(dspaceServicesFactory.getConfigurationService()).thenReturn(configurationService);
//
//        // Mock estático de EPersonServiceFactory
//        ePersonFactoryMock = mockStatic(EPersonServiceFactory.class);
//        EPersonServiceFactory epFactory = mock(EPersonServiceFactory.class);
//        ePersonFactoryMock.when(EPersonServiceFactory::getInstance).thenReturn(epFactory);
//        when(epFactory.getEPersonService()).thenReturn(ePersonService);
//        when(epFactory.getGroupService()).thenReturn(groupService);
//
//        // Mock estático de HttpClient.newBuilder()
//        httpClientStaticMock = mockStatic(HttpClient.class);
//        httpClientStaticMock.when(HttpClient::newBuilder).thenReturn(httpClientBuilder);
//        when(httpClientBuilder.connectTimeout(any())).thenReturn(httpClientBuilder);
//        when(httpClientBuilder.build()).thenReturn(httpClient);
//
//        // Instancia real
//        auth = new ExternalApiAuthentication();
//
//        // Config por defecto
//        when(configurationService.getBooleanProperty(eq("authentication.external.api.insecure_tls"), anyBoolean()))
//                .thenReturn(false);
//        when(configurationService.getIntProperty("authentication.external.api.timeout", 5000))
//                .thenReturn(1500);
//        when(configurationService.getBooleanProperty("authentication.external.api.accept_http200_as_valid", false))
//                .thenReturn(false);
//        when(configurationService.getProperty("authentication.external.api.url"))
//                .thenReturn("https://auth.example/api");
//        when(configurationService.getProperty("authentication.external.api.username"))
//                .thenReturn("apiuser");
//        when(configurationService.getProperty("authentication.external.api.password"))
//                .thenReturn("apipass");
//        when(configurationService.getProperty(eq("authentication.external.api.password.hash"), anyString()))
//                .thenReturn("plain");
//        when(configurationService.getProperty("authentication.external.email_fallback_domain", "usach.cl"))
//                .thenReturn("usach.cl");
//        when(configurationService.getProperty("authentication.external.tipo_to_group", ""))
//                .thenReturn("ESTUDIANTE=Alumnos,ACADEMICO=Academicos");
//        when(configurationService.getBooleanProperty("authentication.external.autoprovision", true))
//                .thenReturn(true);
//
//        when(httpReq.getRemoteAddr()).thenReturn("127.0.0.1");
//    }
//
//    @AfterEach
//    void tearDown() {
//        if (dspaceFactoryMock != null) dspaceFactoryMock.close();
//        if (ePersonFactoryMock != null) ePersonFactoryMock.close();
//        if (httpClientStaticMock != null) httpClientStaticMock.close();
//    }
//
//    @Test
//    void authenticate_success_creaUsuario_yAgregaAGrupo() throws Exception {
//        String body = "{\n" +
//                "  \"success\": true,\n" +
//                "  \"data\": { \"user\": \"juan.perez\", \"tipo\": \"ESTUDIANTE\", \"firstName\": \"Juan\", \"lastName\": \"Pérez\" }\n" +
//                "}";
//        when(httpClient.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
//                .thenReturn(httpResponse);
//        when(httpResponse.statusCode()).thenReturn(200);
//        when(httpResponse.body()).thenReturn(body);
//
//        // EPerson no existe -> autoprovision
//        when(ePersonService.findByEmail(eq(context), eq("juan.perez@usach.cl")))
//                .thenReturn(null);
//        when(ePersonService.create(context)).thenReturn(eperson);
//
//        // Grupo existe y aún no es miembro
//        when(groupService.findByName(eq(context), eq("Alumnos"))).thenReturn(group);
//        when(groupService.isMember(eq(context), eq(eperson), eq(group))).thenReturn(false);
//
//        int result = auth.authenticate(context, "juan.perez", "secreto", null, httpReq);
//
//        assertEquals(ExternalApiAuthentication.SUCCESS, result);
//
//        InOrder inOrder = inOrder(ePersonService, groupService, context);
//        inOrder.verify(context).turnOffAuthorisationSystem();
//        inOrder.verify(ePersonService).create(context);
//        verify(eperson).setEmail("juan.perez@usach.cl");
//        verify(eperson).setNetid("juan.perez");
//        verify(eperson).setCanLogIn(true);
//        verify(ePersonService).update(eq(context), eq(eperson));
//
//        verify(groupService).findByName(eq(context), eq("Alumnos"));
//        verify(groupService).addMember(eq(context), eq(group), eq(eperson));
//        verify(groupService).update(eq(context), eq(group));
//
//        inOrder.verify(context).restoreAuthSystemState();
//        verify(context).setCurrentUser(eperson);
//    }
//
//    @Test
//    void authenticate_badArgs_usernameVacio() throws Exception {
//        int result = auth.authenticate(context, " ", "x", null, httpReq);
//        assertEquals(ExternalApiAuthentication.BAD_ARGS, result);
//        verifyNoInteractions(ePersonService, groupService);
//    }
//
//    @Test
//    void authenticate_httpNo200_badCredentials() throws Exception {
//        when(httpClient.send(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenReturn(httpResponse);
//        when(httpResponse.statusCode()).thenReturn(401);
//
//        int result = auth.authenticate(context, "user", "pass", null, httpReq);
//        assertEquals(ExternalApiAuthentication.BAD_CREDENTIALS, result);
//    }
//
//    @Test
//    void authenticate_jsonInvalido_noSuchUser() throws Exception {
//        when(httpClient.send(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenReturn(httpResponse);
//        when(httpResponse.statusCode()).thenReturn(200);
//        when(httpResponse.body()).thenReturn("no_es_json");
//
//        int result = auth.authenticate(context, "user", "pass", null, httpReq);
//        assertEquals(ExternalApiAuthentication.NO_SUCH_USER, result);
//    }
//
//    @Test
//    void authenticate_configFaltante_noSuchUser() throws Exception {
//        // Provoca IllegalStateException en required("authentication.external.api.url")
//        when(configurationService.getProperty("authentication.external.api.url")).thenReturn(null);
//
//        int result = auth.authenticate(context, "user", "pass", null, httpReq);
//        assertEquals(ExternalApiAuthentication.NO_SUCH_USER, result);
//    }
//}
