
import React, { useState } from 'react';
import { User } from '../types'; // Adjust path as needed

interface UserTourProps {
  user: User;
  onClose: (completed: boolean) => void;
}

interface TourStep {
  title: string;
  content: React.ReactNode;
}

const UserTour: React.FC<UserTourProps> = ({ user, onClose }) => {
  const [currentStep, setCurrentStep] = useState(0);

  const tourSteps: TourStep[] = [
    {
      title: "Welcome to the Task Assignment Assistant!",
      content: (
        <p>
          Hi <strong>{user.displayName}</strong>! Let's take a quick look at how things work to get you started.
        </p>
      ),
    },
    {
      title: "Your Assignments",
      content: (
        <>
          <p>The 'My Assignments' page (often your landing page after login) is where you'll find tasks specifically assigned to you.</p>
          <p className="mt-2">Here, you can see their current status, deadlines, and other important details.</p>
        </>
      ),
    },
    {
      title: "Accept or Decline Tasks",
      content: (
        <>
          <p>When a new task is proposed to you, it will appear in 'My Assignments' with options to 'Accept Task' or 'Decline Task'.</p>
          <p className="mt-2">Your prompt response helps your administrator plan effectively!</p>
        </>
      ),
    },
    {
      title: "Completing Tasks",
      content: (
        <>
          <p>Once you've finished an accepted task, go to 'My Assignments', find the task, and use the 'Mark as Completed / Submit' button.</p>
          <p className="mt-2">If your submission is past the deadline, the system may ask you to provide a brief reason for the delay.</p>
        </>
      ),
    },
    {
      title: "Discover More Tasks",
      content: (
        <>
          <p>Curious about other available work or want to see what's generally available? Check the 'Available Tasks' section in the navigation.</p>
          <p className="mt-2">This page lists tasks that haven't been assigned yet or are open for users to view.</p>
        </>
      ),
    },
    {
      title: "Keep Your Profile Updated",
      content: (
        <>
          <p>In the 'My Profile' section, you can update your contact details, add your interests (which can help in task matching!), and change your system password.</p>
          <p className="mt-2">Keeping your profile accurate helps the system work better for you.</p>
        </>
      ),
    },
  ];

  const handleNext = () => {
    if (currentStep < tourSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    } else {
      onClose(true); // Completed
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleSkip = () => {
    onClose(false); // Skipped
  };
  
  const step = tourSteps[currentStep];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[60] p-4" role="dialog" aria-modal="true" aria-labelledby="user-tour-title">
      <div className="bg-surface rounded-lg shadow-xl p-6 w-full max-w-md transform transition-all">
        <h2 id="user-tour-title" className="text-xl font-semibold text-primary mb-4">{step.title}</h2>
        <div className="text-sm text-textlight space-y-3 mb-6 min-h-[100px]">
          {step.content}
        </div>
        <div className="flex justify-between items-center mt-6 pt-4 border-t border-gray-200">
          <div>
            {currentStep > 0 && (
              <button
                onClick={handlePrevious}
                className="btn-neutral px-3 py-1.5 text-sm mr-2"
              >
                Previous
              </button>
            )}
          </div>
          <div className="flex items-center">
             <button
                onClick={handleSkip}
                className="text-sm text-neutral hover:text-texthighlight mr-4"
              >
                Skip Tour
              </button>
            {currentStep < tourSteps.length - 1 ? (
              <button
                onClick={handleNext}
                className="btn-primary px-3 py-1.5 text-sm"
              >
                Next
              </button>
            ) : (
              <button
                onClick={() => onClose(true)}
                className="btn-success px-3 py-1.5 text-sm"
              >
                Finish Tour
              </button>
            )}
          </div>
        </div>
         <div className="text-center mt-3">
            <p className="text-xs text-neutral">Step {currentStep + 1} of {tourSteps.length}</p>
          </div>
      </div>
    </div>
  );
};

export default UserTour;
