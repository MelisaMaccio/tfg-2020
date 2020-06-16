package es.upm.dit.tfg.ontology;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLObjectPropertyExpression;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.semanticweb.owlapi.reasoner.structural.StructuralReasonerFactory;


public class TotalRisks {
	
	// API2 - obtiene las amenazas y salvaguardas que afectan los riesgos y calcula sus impactos y probabilidades
	// tambien los clasifica según su impacto y probabilidad

	public static void main( String[] args ) {
		
		//Lista riesgos, impactos y probabilidades
		String[] risks = InitialInstances.risksList();
		HashMap<String, Float> riskImpacts = new HashMap<String, Float>();
		HashMap<String, Float> riskProbabilities = new HashMap<String, Float>();
		HashMap<String, Float> riskImpactsS = new HashMap<String, Float>();
		HashMap<String, Float> riskProbabilitiesS = new HashMap<String, Float>();

		//Inicialización
	    OWLOntologyManager manager = OWLManager.createOWLOntologyManager();
	    OWLOntology onto = null;
	    try {
	    	onto = InitialInstances.loadOntology(manager);
	    
		    
		    OWLDataFactory factory = manager.getOWLDataFactory();
		    OWLReasonerFactory reasonerFactory = new StructuralReasonerFactory();
	        OWLReasoner reasoner = reasonerFactory.createReasoner(onto);
					
		    IRI ontoIRI = onto.getOntologyID().getOntologyIRI().get();
		    System.out.println(ontoIRI);
		    
		  //Properties
	        OWLObjectProperty isGeneratedBy = factory.getOWLObjectProperty(IRI.create("http://www.semanticweb.org/paulagarcia/ontologies/2020/2/cyberthreat_STIXDRM#isGeneratedBy"));
	        OWLObjectProperty isMitigatedBy = factory.getOWLObjectProperty(IRI.create("http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_DRM#isMitigatedBy"));
	        OWLObjectProperty evaluates = factory.getOWLObjectProperty(IRI.create("http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_DRM#evaluates"));
	        OWLObjectProperty hasImpactOf = factory.getOWLObjectProperty(IRI.create("http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_DRM#hasImpactOf"));
	        OWLObjectProperty hasProbabilityOf = factory.getOWLObjectProperty(IRI.create("http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_DRM#hasProbabilityOf"));

	        OWLDataProperty impact = factory.getOWLDataProperty(IRI.create("http://www.semanticweb.org/paulagarcia/ontologies/2020/2/cibersituational-ontology-test2#impact"));
	        OWLDataProperty probability = factory.getOWLDataProperty(IRI.create("http://www.semanticweb.org/paulagarcia/ontologies/2020/2/cibersituational-ontology-test2#probability"));
	        OWLDataProperty type = factory.getOWLDataProperty(IRI.create("http://www.semanticweb.org/paulagarcia/ontologies/2020/2/cibersituational-ontology-test2#type"));

	        
		    for (String risk : risks) {
		    	String indName = risk + "_Risk";
		    	String className = indName.replaceAll("_", "");
		    	String indType = risk.replaceAll("_", "") + "ResidualRisk";
		        String classNameS = "ResidualRisk";
		        
				for (OWLClass clss : onto.getClassesInSignature()) {
					
					Float threatsImpact = (float) 0;
					Float threatsProbability = (float) 0;
					Float safeguardsImpact = (float) 0;
					Float safeguardsProbability = (float) 0;
					
			        // Buscamos el impacto y la probabilidad de las amenazas que afectan a cada riesgo
					// Identificamos el riesgo que estamos buscando
					if(clss.getIRI().getFragment().equals(className)){
						
						//Obtenemos los individuos de la clase
						Set<OWLNamedIndividual> instances = reasoner.getInstances(clss, true).getFlattened();
						
						//Obtenemos los individuos relacionados con los riesgos mediante la Object Property
						Set<OWLNamedIndividual> relatedInds = getRelatedIndividuals(reasoner, isGeneratedBy, instances);
						
						// Obtenemos los valores del impacto de los eventos que afectan al riesgo
						for (OWLNamedIndividual ind : relatedInds) {
							Float data = Float.parseFloat(getDataProperties(onto, impact, ind));
							
							threatsImpact += data;
						}
						
						// Obtenemos los valores de la probabilidad de los eventos que afectan al riesgo
						for (OWLNamedIndividual ind : relatedInds) {
							Float data = Float.parseFloat(getDataProperties(onto, probability, ind));
							
							threatsProbability += data;
						}
						
						// Guardamos los impactos y probabilidades de las amenazas que afectan a los riesgos
						if (riskImpacts.get(indName) == null) {
							riskImpacts.put(indName, threatsImpact);
						} else {
							riskImpacts.put(indName, (riskImpacts.get(indName) + threatsImpact));
						}
						
						if (riskProbabilities.get(indName) == null) {
							riskProbabilities.put(indName, threatsProbability);
						} else {
							riskProbabilities.put(indName, (riskProbabilities.get(indName) + threatsProbability));
						}
					}
					
					
					
					
				    // Buscamos el impacto y la probabilidad de las salvaguardas que afectan a cada riesgo
					// Identificamos el riesgo residual que estamos buscando
					if(clss.getIRI().getFragment().equals(classNameS)){
					    
						Set<OWLNamedIndividual> instances = new HashSet<OWLNamedIndividual>();

						//Obtenemos los individuos de la clase Residual Risk
						Set<OWLNamedIndividual> allInstances = reasoner.getInstances(clss, true).getFlattened();
						
						//Filtramos los individuos del tipo de riesgo que buscamos
						for (OWLNamedIndividual ind : allInstances) {
							String nameInd = getDataProperties(onto, type, ind);
							
							if (indType.replaceAll("\\s", "").equals(nameInd.replaceAll("\\s", ""))) {
								instances.add(ind);
							}
						}
						
						//Obtenemos los individuos relacionados con los riesgos mediante la Object Property
						Set<OWLNamedIndividual> relatedInds = getRelatedIndividuals(reasoner, isMitigatedBy, instances);
						
						// Obtenemos los valores del impacto de los eventos que afectan al riesgo
						for (OWLNamedIndividual ind : relatedInds) {
							Float data = Float.parseFloat(getDataProperties(onto, impact, ind));
							
							safeguardsImpact += data;
						}
						
						// Obtenemos los valores de la probabilidad de los eventos que afectan al riesgo
						for (OWLNamedIndividual ind : relatedInds) {
							Float data = Float.parseFloat(getDataProperties(onto, probability, ind));
							
							safeguardsProbability += data;
						}
						
						// Los impactos y probabilidades de las salvaguardas se restan a los de los riesgos
						if (riskImpactsS.get(indName) == null) {
							riskImpactsS.put(indName, safeguardsImpact);
						} else {
							riskImpactsS.put(indName, (riskImpactsS.get(indName) + safeguardsImpact));
						}
						
						if (riskProbabilitiesS.get(indName) == null) {
							riskProbabilitiesS.put(indName, safeguardsProbability);
						} else {
							riskProbabilitiesS.put(indName, (riskProbabilitiesS.get(indName) + safeguardsProbability));
						}
					}
				}
		    }
		    
		    
		    //Guardamos el impacto y probabilidad en los potential y residual risks
		    for (String risk : risks) {
		    	String name = risk + "_Risk"; 
		    	String className = name.replaceAll("_", "");
		    	String typeP = risk.replaceAll("_", "") + "PotentialRisk";
		    	String typeR = risk.replaceAll("_", "") + "ResidualRisk";
		    	Float totalImpact = (float) 0;
		    	Float totalProbability = (float) 0;
		    	String classByImpact = "";
		    	String classByProbability = "";
		    	
		    
				for (OWLClass clss : onto.getClassesInSignature()) {
											
					//Obtenemos los individuos de la clase
					Set<OWLNamedIndividual> instances = reasoner.getInstances(clss, true).getFlattened();
				
					for (OWLNamedIndividual ind : instances) {
						String nameInd = getDataProperties(onto, type, ind);
						
						//Guarda en los potential risks las propiedades de las amenazas
						if (typeP.replaceAll("\\s", "").equals(nameInd.replaceAll("\\s", ""))) {
							
							removeAxiom(onto, impact, ind, manager);
							removeAxiom(onto, probability, ind, manager);
							setDataProperties(onto, impact, ind, manager, factory, riskImpacts.get(name));
							setDataProperties(onto, probability, ind, manager, factory, riskProbabilities.get(name));
						}
						
						////Guarda en los residual risks las propiedades de las amenazas menos las de las salvaguardas
						if (typeR.replaceAll("\\s", "").equals(nameInd.replaceAll("\\s", ""))) {
							
							removeAxiom(onto, impact, ind, manager);
							removeAxiom(onto, probability, ind, manager);
							setDataProperties(onto, impact, ind, manager, factory, (riskImpacts.get(name)-riskImpactsS.get(name)));
							setDataProperties(onto, probability, ind, manager, factory, (riskProbabilities.get(name)-riskProbabilitiesS.get(name)));
						}
					}
					
					//Buscamos la clase del riesgo
					if(clss.getIRI().getFragment().equals(className)){
					
						totalImpact = riskImpacts.get(name)-riskImpactsS.get(name);
						totalProbability = riskProbabilities.get(name)-riskProbabilitiesS.get(name);
						classByImpact = classifyByImpact(totalImpact);
						classByProbability = classifyByProbability(totalProbability);
						
						//Creamos un individuo de la clase RiskImpact segun su impacto
						OWLNamedIndividual impactClassification = InitialInstances.createInstances(manager, factory, onto, ontoIRI, 
								(classByImpact + "_Impact_" + name), (classByImpact + "ImpactRisk"));
						
						//Creamos un individuo de la clase RiskProbability segun su probabilidad
						OWLNamedIndividual probabilityClassification = InitialInstances.createInstances(manager, factory, onto, ontoIRI, 
								(classByProbability + "_Probability_" + name), (classByProbability + "RiskProbability"));
						
						Set<OWLNamedIndividual> inds = reasoner.getInstances(clss, true).getFlattened();
						
						//Asociamos los riesgos con su respectivo RiskImpact y RiskProbability
						for (OWLNamedIndividual ind : inds) {
							
							setObjectProperties(onto, hasImpactOf, manager, factory, ind, impactClassification);
							setObjectProperties(onto, evaluates, manager, factory, impactClassification, ind);							
							setObjectProperties(onto, hasProbabilityOf, manager, factory, ind, probabilityClassification);
						}
					}
				}

				System.out.println("Riesgo: " + name + "\n Impacto: " + classByImpact + " [" + totalImpact + "]" +
						"\n Probabilidad: " + classByProbability + " [" + totalProbability + "]\n ------------------");
		    }
		    
		    InitialInstances.saveOnto(onto, manager);
		    System.out.println("Fin.");
		    
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	}
	
	//Obtiene los individuos relacionados con una estancia a traves de una object property
	public static Set<OWLNamedIndividual> getRelatedIndividuals(OWLReasoner reasoner, OWLObjectProperty prop, Set<OWLNamedIndividual> instances) {
	    
		Set<OWLNamedIndividual> relatedInds = new HashSet<OWLNamedIndividual>();
		if (instances == null) {
			return relatedInds;
		}
		
		for (OWLNamedIndividual i : instances) {
			Set<OWLNamedIndividual> auxInds = reasoner.getObjectPropertyValues(i, prop).getFlattened();
			for (OWLNamedIndividual j : auxInds) {
	            relatedInds.add(j);
			}
		}
		
        return relatedInds;
	}
	
	//Obtiene los valores de una data property de un individuo
	public static String getDataProperties(OWLOntology onto, OWLDataProperty prop, OWLNamedIndividual ind) {
		
		String result = "0";
		
		Set<OWLDataPropertyAssertionAxiom> dataProps = onto.getDataPropertyAssertionAxioms(ind);
		if (dataProps == null) {
			return result;
		}
		
		for (OWLDataPropertyAssertionAxiom axiom : dataProps) {
            if(axiom.getProperty().equals(prop) && axiom.getSubject().equals(ind)) {
            	result = axiom.getObject().getLiteral().toString();
            }
		}
		
        return result;
	}
	
	//Elimina un axioma
	public static void removeAxiom(OWLOntology onto, OWLDataProperty prop, OWLNamedIndividual ind, OWLOntologyManager manager) {
		
		Set<OWLDataPropertyAssertionAxiom> dataProps = onto.getDataPropertyAssertionAxioms(ind);
		
		for (OWLDataPropertyAssertionAxiom axiom : dataProps) {
            if(axiom.getProperty().equals(prop) && axiom.getSubject().equals(ind)) {
            	manager.removeAxiom(onto, axiom);
            }
		}
	}
	
	//Crea axiomas de un individuo con una data property y su valor
	public static void setDataProperties(OWLOntology onto, OWLDataProperty prop, OWLNamedIndividual ind, OWLOntologyManager manager, 
		OWLDataFactory factory, Float value) {
		
		OWLDataPropertyAssertionAxiom axiom;
		
		axiom = factory.getOWLDataPropertyAssertionAxiom(prop, ind, value);
		
		manager.addAxiom(onto, axiom);
	}
	
	//Crea axiomas de un individuo con una object property y su valor
	public static void setObjectProperties(OWLOntology onto, OWLObjectPropertyExpression prop, OWLOntologyManager manager, 
		OWLDataFactory factory, OWLNamedIndividual ind, OWLNamedIndividual ind2) {
		
		OWLObjectPropertyAssertionAxiom axiom;
		
		axiom = factory.getOWLObjectPropertyAssertionAxiom(prop, ind, ind2);
		
		manager.addAxiom(onto, axiom);
	}
	
	//Clasifica los riesgos segun su impacto
	public static String classifyByImpact(Float impact) {
		if (impact <= 2) {
			return "VeryLow";
		} else if (impact <= 4) {
			return "Low";
		} else if (impact <= 6) {
			return "Medium";
		} else if (impact <= 6) {
			return "High";
		} else {
			return "Critical";
		}
	}
	
	//Clasifica los riesgos segun su probabilidad
	public static String classifyByProbability(Float prob) {
		if (prob <= 2) {
			return "VeryLow";
		} else if (prob <= 4) {
			return "Low";
		} else if (prob <= 6) {
			return "Medium";
		} else if (prob <= 8) {
			return "High";
		} else {
			return "Extreme";
		}
	}
}