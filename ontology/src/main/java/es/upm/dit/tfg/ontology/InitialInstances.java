package es.upm.dit.tfg.ontology;

import java.io.File;

import org.junit.Ignore;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.util.DefaultPrefixManager;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLNamedIndividual;

public class InitialInstances {

	// API1 - crea instancias de todos los riesgos para inicializar la ontologia
	
	public static void main( String[] args ) {

		//Lista de riesgos
		String[] risks = risksList();
		
		//Inicialización
        OWLOntologyManager manager = OWLManager.createOWLOntologyManager();
        OWLOntology onto = null;
        OWLDataFactory factory = manager.getOWLDataFactory();
        
				
        try {
        	onto = loadOntology(manager);
        
	        IRI ontoIRI = onto.getOntologyID().getOntologyIRI().get();
	        System.out.println(ontoIRI);
	        
	        //Bucle riesgos
	        for(int i = 0; i < risks.length; i++) {
	        	String risk = risks[i] + "_Risk";
	            createInstances(manager, factory, onto, ontoIRI, risk, risk.replaceAll("_", ""));
	
	        }
	        
			saveOnto(onto, manager);
	        System.out.println("Fin");

        } catch (Exception e) {
	    	e.printStackTrace();
        }
    }
	
	// Carga la ontología sobre la que trabajaremos
	public static OWLOntology loadOntology(OWLOntologyManager manager) throws OWLOntologyCreationException {
				
		File file = new File("C:\\Users\\melis\\Documents\\Protege\\cibersituational-onto-vacia.owl");
		OWLOntology onto = manager.loadOntologyFromOntologyDocument(file);
		   
		return onto;
		
	}
	
	//Crea instancias
	public static OWLNamedIndividual createInstances(OWLOntologyManager manager, OWLDataFactory factory, OWLOntology onto,
			IRI ontoIRI, String name, String className) {
		
		
		String prefix = "http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_DRM#";
        PrefixManager pm = new DefaultPrefixManager(prefix);
		OWLClass clss = factory.getOWLClass(className, pm);
		
		OWLIndividual ind = factory.getOWLNamedIndividual(IRI.create(prefix + name));
		OWLClassAssertionAxiom classAssert = factory.getOWLClassAssertionAxiom(clss, ind);
		
		manager.addAxiom(onto, classAssert);
		
		return (OWLNamedIndividual) classAssert.getIndividual();
	}
	
	@Ignore
	public static void saveOnto(OWLOntology onto, OWLOntologyManager manager) {
		
		IRI documentIRI = manager.getOntologyDocumentIRI(onto);
		try {
			manager.saveOntology(onto, documentIRI);
		} catch (Exception e) {
			System.out.println("Ha habido un error al guardar.");
		}
	}
	
	public static String[] risksList() {
		String[] risks = {"Data_Protection_Compliance", "Other_Legal_Compliance", "Configuration_Error",
				"Deliberated_Config_Files_Tampering", "Deliberated_HW_Tampering", "Deliberated_Information_Destruction",
				"Deliberated_Information_Leak", "Deliberated_Information_Tampering", "Deliberated_Malicious_SW_Distribution",
				"Deliberated_Registers_Tampering", "Deliberated_SW_Tampering", "Deliberated_Unauthorized_Access", 
				"Denial_Of_Service", "Device_Lost", "Device_Theft", "Human_Resources_Not_Available",
				"HW_Maintenance_Error", "Idetity_Thief", "Logical_Failure", "Monitoring_Error",
				"Network_Outage", "NonIntentional_Admin_Error", "NonIntentional_Information_Destruction",
				"NonIntentional_Information_Leak", "NonIntentional_Information_Tampering",
				"NonIntentional_Malicious_SW_Distribution", "NonIntentional_User_Error", "Physical_Failure",
				"Power_Outage", "Social_Engineering", "SW_Maintenance_Error", "SW_Vulnerabilities", "Accident",
				"Fire", "Flooding", "Natural_Disaster", "Terrorism_Attack", "Corporate_Brand_Image_Damage",
				"Delayed_Delivery", "Stakeholders_Satidfaction", "Technical_Complexity_Derived", "Untrustworthy",
				"Users_Complaints", "Bad_Reputation", "Economic_Loss", "Partnership", "Press_Negative_Impact",
				"Stakeholders","Strategic_Objective", "Other"}; 
		return risks;
	}
	
}
