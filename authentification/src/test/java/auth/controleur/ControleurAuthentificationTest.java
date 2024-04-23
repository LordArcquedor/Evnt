package auth.controleur;

import auth.AuthentificationApplication;
import auth.dto.UtilisateurDTO;
import auth.exception.*;
import auth.facade.FacadeAuthentificationImpl;
import auth.modele.Utilisateur;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.when;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = AuthentificationApplication.class)
@AutoConfigureMockMvc
public class ControleurAuthentificationTest {

    @Autowired
    MockMvc mvc;
    @MockBean
    FacadeAuthentificationImpl facade;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    Function<Utilisateur,String> genereToken;
    @MockBean
    JwtEncoder jwtEncoder;


    @Test
    public void inscription_ok() throws Exception{

        String pseudo = "utilisateur";
        String mdp = "motdepasse";
        String eMail = "utilisateur@example.com";

        UtilisateurDTO utilisateurDTO = new UtilisateurDTO();
        utilisateurDTO.setEmail(eMail);
        utilisateurDTO.setPseudo(pseudo);
        utilisateurDTO.setMdp(mdp);

        Mockito.doNothing().when(facade).inscription(pseudo, mdp, eMail);

        MvcResult mvcResult = mvc.perform(post("/auth/inscription")
                        .param("pseudo", pseudo)
                        .param("mdp", mdp)
                        .param("eMail", eMail))
                .andExpect(status().isCreated())
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Compte créé !", responseBody);

        Mockito.verify(facade, Mockito.times(1)).inscription(pseudo, mdp, eMail);
    }


    @Test
    public void inscription_ko_pseudoDejaPris() throws Exception {
        String pseudo = "utilisateur";
        String mdp = "motdepasse";
        String eMail = "utilisateur@example.com";

        // Configuration de la simulation pour lancer une PseudoDejaPrisException
        Mockito.doThrow(new PseudoDejaPrisException()).when(facade).inscription(pseudo, mdp, eMail);

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/inscription")
                        .param("pseudo", pseudo)
                        .param("mdp", mdp)
                        .param("eMail", eMail))
                .andExpect(status().isConflict()) // On s'attend à une réponse avec un code 409 (CONFLICT)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Pseudo " + pseudo + " déjà pris", responseBody);

        // Vérification que la méthode inscription de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).inscription(pseudo, mdp, eMail);
    }

    @Test
    public void inscription_emailDejaPris() throws Exception {
        String pseudo = "utilisateur";
        String mdp = "motdepasse";
        String eMail = "utilisateur@example.com";

        // Configuration de la simulation pour lancer une EMailDejaPrisException
        Mockito.doThrow(new EMailDejaPrisException()).when(facade).inscription(pseudo, mdp, eMail);

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/inscription")
                        .param("pseudo", pseudo)
                        .param("mdp", mdp)
                        .param("eMail", eMail))
                .andExpect(status().isConflict()) // On s'attend à une réponse avec un code 409 (CONFLICT)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Email " + eMail + " déjà existante", responseBody);

        // Vérification que la méthode inscription de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).inscription(pseudo, mdp, eMail);
    }


    @Test
    public void inscription_emailOuPseudoDejaPris() throws Exception {
        String pseudo = "utilisateur";
        String mdp = "motdepasse";
        String eMail = "utilisateur@example.com";

        // Configuration de la simulation pour lancer une EmailOuPseudoDejaPrisException
        Mockito.doThrow(new EmailOuPseudoDejaPrisException()).when(facade).inscription(pseudo, mdp, eMail);

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/inscription")
                        .param("pseudo", pseudo)
                        .param("mdp", mdp)
                        .param("eMail", eMail))
                .andExpect(status().isConflict()) // On s'attend à une réponse avec un code 409 (CONFLICT)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Email ou pseudo déjà existante", responseBody);

        // Vérification que la méthode inscription de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).inscription(pseudo, mdp, eMail);
    }


    @Test
    public void connexion_ok() throws Exception {
        String pseudo = "utilisateur";
        String mdp = "motdepasse";
        String email ="email@test.com";

        // Création d'un utilisateur simulé pour le test
        Utilisateur utilisateur = new Utilisateur();
        utilisateur.setPseudo(pseudo);
        utilisateur.setMdp(mdp);
        utilisateur.seteMail(email);


        Jwt jwt = Jwt.withTokenValue("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZSIsImlhdCI6MTYxNjI0MDQ1NSwiZXhwIjoxNjE2MjQwNTQ1fQ.7jzr06q2Q5BcWwKU-GT1HkhwE16KZ6xN4v6PtnfI_9M")
                .header("alg", "HS256")
                .claim("sub", "user")
                .build();


        // Simulation de la méthode connexion pour renvoyer un utilisateur
        when(facade.connexion(pseudo, mdp)).thenReturn(utilisateur);

        // Simulation de la génération du token
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZSIsImlhdCI6MTYxNjI0MDQ1NSwiZXhwIjoxNjE2MjQwNTQ1fQ.7jzr06q2Q5BcWwKU-GT1HkhwE16KZ6xN4v6PtnfI_9M";
        when(jwtEncoder.encode(Mockito.any())).thenReturn(jwt);

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/connexion")
                        .param("pseudo", pseudo)
                        .param("mdp", mdp))
                .andExpect(status().isOk()) // On s'attend à une réponse avec un code 200 (OK)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Bearer " + token, responseBody);

        // Vérification des en-têtes de la réponse
        String authorizationHeader = mvcResult.getResponse().getHeader(HttpHeaders.AUTHORIZATION);
        assertNotNull(authorizationHeader);
        assertEquals("Bearer " + token, authorizationHeader);

        // Vérification que la méthode connexion de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).connexion(pseudo, mdp);
    }


    @Test
    public void connexion_utilisateurInexistant() throws Exception {
        String pseudo = "utilisateur";
        String mdp = "motdepasse";

        // Simulation de la méthode connexion pour lancer une UtilisateurInexistantException
        when(facade.connexion(pseudo, mdp)).thenThrow(new UtilisateurInexistantException());

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/connexion")
                        .param("pseudo", pseudo)
                        .param("mdp", mdp))
                .andExpect(status().isNotFound()) // On s'attend à une réponse avec un code 404 (NOT FOUND)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Mauvais identifiant !", responseBody);

        // Vérification que la méthode connexion de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).connexion(pseudo, mdp);
    }

    @Test
    public void connexion_mauvais_mdp() throws Exception {
        String pseudo = "utilisateur";
        String mdp = "mauvaismotdepasse";

        // Simulation de la méthode connexion pour lancer une MdpIncorrecteException
        when(facade.connexion(pseudo, mdp)).thenThrow(MdpIncorrecteException.class);

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/connexion")
                        .param("pseudo", pseudo)
                        .param("mdp", mdp))
                .andExpect(status().isUnauthorized()) // On s'attend à une réponse avec un code 401 (Unauthorized)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Mauvais mdp !", responseBody);

        // Vérification que la méthode connexion de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).connexion(pseudo, mdp);
    }


    @Test
    public void deconnexion_reussie_() throws Exception {
        String pseudo = "pseudo";

        // Création d'un utilisateur simulé pour le test
        Utilisateur utilisateur = new Utilisateur();
        utilisateur.setPseudo(pseudo);
        utilisateur.seteMail("email@gmail.com");
        utilisateur.setMdp("mdp");

        // Simulation de la génération du token
        Jwt jwt = Jwt.withTokenValue("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VybmFtZSIsImlhdCI6MTYxNjI0MDQ1NSwiZXhwIjoxNjE2MjQwNTQ1fQ.7jzr06q2Q5BcWwKU-GT1HkhwE16KZ6xN4v6PtnfI_9M")
                .header("alg", "HS256")
                .claim("sub", "user")
                .build();
        String token = "Bearer " + jwt.getTokenValue();

        // Simulation de la déconnexion réussie
        Mockito.doNothing().when(facade).deconnexion(pseudo);

        // Simulation de la génération du token
        when(genereToken.apply(utilisateur)).thenReturn(token);

        // Exécution de la requête simulée
        mvc.perform(post("/auth/deconnexion")
                        .param("pseudo", pseudo))
                .andExpect(status().isOk()) // On s'attend à une réponse avec un code 200 (OK)
                .andExpect(content().string("Déconnexion de " + pseudo + " faite !"));

        // Vérification que la méthode deconnexion de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).deconnexion(pseudo);
    }

    //TODO FIXE
    @Test
    public void deconnexion_reussie() throws Exception {
        String pseudo = "pseudo";
        Utilisateur j = new Utilisateur();
        j.setPseudo("pseudo");
        j.seteMail("email@gmail.com");
        j.setMdp("mdp");

        String token = "Bearer "+genereToken.apply(j);


        // Simulation de la déconnexion réussie
        Mockito.doNothing().when(facade).deconnexion(pseudo);


        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/deconnexion")
                        .param("pseudo", pseudo))
                .andExpect(status().isOk()) // On s'attend à une réponse avec un code 200 (OK)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Déconnexion de " + pseudo + " faite !", responseBody);

        // Vérification que la méthode deconnexion de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).deconnexion(pseudo);
    }


    //TODO FIXE
    @Test
    public void deconnexion_utilisateur_inexistant() throws Exception {
        String pseudo = "utilisateur";

        // Simulation de l'utilisateur inexistant
        Mockito.doThrow(UtilisateurInexistantException.class).when(facade).deconnexion(pseudo);

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/deconnexion")
                        .param("pseudo", pseudo))
                .andExpect(status().isNotFound()) // On s'attend à une réponse avec un code 404 (NOT FOUND)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Utilisateur inexistant", responseBody);

        // Vérification que la méthode deconnexion de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).deconnexion(pseudo);
    }


    //TODO FIXE
    @Test
    public void deconnexion_utilisateur_deja_deconnecte() throws Exception {
        String pseudo = "utilisateur";

        // Simulation de l'utilisateur déjà déconnecté
        Mockito.doThrow(UtilisateurDejaDeconnecteException.class).when(facade).deconnexion(pseudo);

        // Exécution de la requête simulée
        MvcResult mvcResult = mvc.perform(post("/auth/deconnexion")
                        .param("pseudo", pseudo))
                .andExpect(status().isForbidden()) // On s'attend à une réponse avec un code 403 (FORBIDDEN)
                .andReturn();

        // Vérification du corps de la réponse
        String responseBody = mvcResult.getResponse().getContentAsString();
        assertEquals("Déjà connecté !", responseBody);

        // Vérification que la méthode deconnexion de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).deconnexion(pseudo);
    }


    //TODO FIXE
    @Test
    public void modificationPseudo_succes() throws Exception {
        // Paramètres de la requête
        String pseudo = "ancienPseudo";
        String nouveauPseudo = "nouveauPseudo";

        // Mock de la méthode reSetPseudo dans la façade
        Mockito.doNothing().when(facade).reSetPseudo(pseudo, nouveauPseudo);

        // Exécution de la requête simulée
        mvc.perform(patch("/modification-pseudo")
                        .param("pseudo", pseudo)
                        .param("nouveauPseudo", nouveauPseudo))
                .andExpect(status().isOk()) // On s'attend à une réponse avec un code 200 (OK)
                .andExpect(content().string("Pseudo : " + pseudo + " changé en :" + nouveauPseudo + " !"));

        // Vérification que la méthode reSetPseudo de la façade a été appelée avec les bons paramètres
        Mockito.verify(facade, Mockito.times(1)).reSetPseudo(pseudo, nouveauPseudo);
    }


    //TODO FIXE
    @Test
    public void modificationPseudo_utilisateurInexistant() throws Exception {
        // Paramètres de la requête
        String pseudo = "pseudoInexistant";
        String nouveauPseudo = "nouveauPseudo";

        // Simulation de l'exception UtilisateurInexistantException
        Mockito.doThrow(UtilisateurInexistantException.class)
                .when(facade)
                .reSetPseudo(pseudo, nouveauPseudo);

        // Exécution de la requête simulée
        mvc.perform(patch("/modification-pseudo")
                        .param("pseudo", pseudo)
                        .param("nouveauPseudo", nouveauPseudo))
                .andExpect(status().isNotFound()) // On s'attend à une réponse avec un code 404 (Not Found)
                .andExpect(content().string("Mauvais pseudo !"));
    }


}
