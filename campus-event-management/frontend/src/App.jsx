import React from 'react';
import ExplanationCard from './components/ExplanationCard.jsx';

function Header() {
  return (
    <header className="bg-pastel-pink py-4 shadow-md">
      <h1 className="text-3xl font-bold text-center text-pastel-blue">
        Project Kavach by Abhishek Kothari - 24BCE2610
      </h1>
    </header>
  );
}

function Footer() {
  return (
    <footer className="bg-pastel-green py-2 mt-8 text-center text-sm text-gray-700">
      © 2026 Campus Event Management System – All rights reserved.
    </footer>
  );
}

export default function App() {
  return (
    <div className="flex flex-col min-h-screen font-sans">
      <Header />
      <main className="flex-grow container mx-auto px-4 py-6">
        <ExplanationCard />
        {/* Future components like EventList will go here */}
      </main>
      <Footer />
    </div>
  );
}
