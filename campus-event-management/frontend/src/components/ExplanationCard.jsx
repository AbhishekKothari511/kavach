import React from 'react';

function ExplanationCard() {
  return (
    <section className="max-w-3xl mx-auto p-6 bg-pastel-lavender rounded-lg shadow-md">
      <h2 className="text-2xl font-semibold mb-4 text-pastel-blue">What this site does</h2>
      <p className="text-gray-800 mb-2">
        The Campus Event Management System allows event organizers to create, edit, and publish events for the whole campus.
      </p>
      <p className="text-gray-800 mb-2">
        Students can browse upcoming events, search by keywords or dates, and register online. The system enforces seat limits to avoid over‑booking.
      </p>
      <p className="text-gray-800 mb-2">
        Administrators have a dashboard that shows registration statistics, event attendance, and can manage user roles (admin, organizer, student).
      </p>
      <p className="text-gray-800">
        All data is stored securely in PostgreSQL and protected by JWT‑based authentication.
      </p>
    </section>
  );
}

export default ExplanationCard;
