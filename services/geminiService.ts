
import { GoogleGenAI, GenerateContentResponse } from "@google/genai";
import { Task, User, Program, GeminiSuggestion, Assignment } from '../types';

// Directly use process.env.API_KEY.
// It's assumed that the execution environment (e.g., build process)
// will make this variable available, often from a .env file.
// The typeof checks are a safeguard for client-side environments where 'process'
// might not be defined unless a build tool specifically provides it.
const apiKey: string | undefined = (typeof process !== 'undefined' && process.env && process.env.API_KEY)
    ? process.env.API_KEY
    : undefined;

if (!apiKey) {
  console.error("API_KEY environment variable is not set or accessible. Gemini API functionalities will be unavailable. Please ensure your build process or execution environment defines process.env.API_KEY (e.g., from your .env file or other configuration source).");
}

// Initialize GoogleGenAI. The apiKey property is optional.
// If apiKey is undefined (i.e., not set in the environment), the SDK will be initialized without it.
// Subsequent API calls that require an API key will likely fail, which is the expected behavior.
const ai = new GoogleGenAI({ apiKey: apiKey });

// Updated to accept assignments to filter users
export const getAssignmentSuggestion = async (task: Task, users: User[], programs: Program[], assignments: Assignment[]): Promise<GeminiSuggestion | null> => {
  if (!apiKey) { // Check if API key is available before making a call.
    return { suggestedPersonName: null, justification: "AI suggestions are unavailable: API key is not configured. Please check environment configuration or contact an administrator." };
  }
  
  const model = 'gemini-2.5-flash-preview-04-17';

  const programName = task.programId ? programs.find(p => p.id === task.programId)?.name : null;

  // Filter out users who already have an active task
  const activeUserIdsWithTasks = assignments
    .filter(a => a.status === 'pending_acceptance' || a.status === 'accepted_by_user')
    .map(a => a.personId);
  const availableUsers = users.filter(u => u.role === 'user' && !activeUserIdsWithTasks.includes(u.id));


  const taskDetails = `
    Task Title: ${task.title}
    Task Description: ${task.description}
    Required Skills for Task: ${task.requiredSkills}
    ${programName ? `Related Program: ${programName}` : ''}
  `;

  const userProfiles = availableUsers.map((u, index) => `
    Person ${index + 1}:
    Display Name: ${u.displayName}
    Unique ID (for reference, do not include in suggestion): ${u.uniqueId}
    Position: ${u.position} (This is their general role or primary skillset category)
    User Interests: ${u.userInterests} (These are specific interests declared by the user. Consider if these align with the task or its related program: ${programName || 'N/A'})
  `).join('\n');

  const prompt = `
    You are an expert HR assistant specializing in matching skilled individuals to tasks within an organizational context (e.g., IEEE events, company projects).
    Your goal is to find the best fit considering a diverse range of capabilities, suitable for both technical and non-technical roles.
    IMPORTANT: Only suggest individuals from the provided list of available people. These people do not currently have any other active tasks.
    
    Given the following task details:
    ${taskDetails}

    And the following available people (who do not have other active tasks):
    ${userProfiles.length > 0 ? userProfiles : "No people available or all available people already have active tasks."}

    Suggest the most suitable person (by their Display Name) for this task.
    Prioritize matching based on:
    1. Required skills for the task, and how well the person's "Position" aligns with these requirements.
    2. Person's stated "User Interests", especially if they align with the task title, description, or any related program.
    3. General alignment of "Position" and "User Interests", applicable to a wide variety of roles (technical, administrative, organizational, creative, etc.).

    If the task is related to a specific program, consider people whose "User Interests" explicitly mention that program or related keywords.

    Provide the display name of the person and a brief justification for your choice.
    If no one is a good fit or no people are available, clearly state that.
    
    Format your response STRICTLY as a JSON object with the following structure:
    {
      "suggestedPersonName": "Display Name of the person OR null if no one is suitable",
      "justification": "Your brief reasoning here. If no one, explain why."
    }
  `;

  try {
    const response: GenerateContentResponse = await ai.models.generateContent({
      model: model,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        temperature: 0.4 
      } 
    });

    let jsonStr = response.text.trim();
    const fenceRegex = /^```(\w*)?\s*\n?(.*?)\n?\s*```$/s;
    const match = jsonStr.match(fenceRegex);
    if (match && match[2]) {
      jsonStr = match[2].trim();
    }
    
    const suggestion = JSON.parse(jsonStr) as GeminiSuggestion;
    // If AI suggests a user not in the filtered availableUsers list (shouldn't happen with good prompt), treat as no suggestion
    if (suggestion.suggestedPersonName && !availableUsers.find(u => u.displayName === suggestion.suggestedPersonName)) {
        return { suggestedPersonName: null, justification: "AI suggested a user not available for new tasks or an invalid user." };
    }
    return suggestion;

  } catch (error) {
    console.error("Error calling Gemini API:", error);
    let errorMessage = "Failed to get suggestion from AI. ";
    if (error instanceof Error) {
      errorMessage += error.message;
    }
    // More specific error handling for common issues
    if (error && typeof error === 'object' && 'message' in error && typeof error.message === 'string') {
        if (error.message.includes(' हरिनाम') || error.message.toLowerCase().includes('safety') || error.message.toLowerCase().includes('blocked')) {
            errorMessage = "AI suggestion was declined or blocked, possibly due to safety settings or content policies. Please try rephrasing or contact support if this persists.";
        } else if (error.message.toLowerCase().includes('api key') || error.message.toLowerCase().includes('authentication')) {
             errorMessage = "AI suggestions are unavailable: API key is invalid, missing, or caused an authentication error. Please contact an administrator.";
        }
    }
    return { suggestedPersonName: null, justification: errorMessage };
  }
};
