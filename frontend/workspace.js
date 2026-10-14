(() => {
  const copy = {
    analysis: ['Analysis studio', 'Understand every APK.', 'Inspect suspicious Android apps and turn extracted evidence into a clear assessment.'],
    history: ['Sample history', 'Return to the evidence.', 'Open a saved analysis to review its findings or export a report.'],
    folders: ['Folder runs', 'Your investigations, together.', 'Review completed folder runs and inspect each APK independently.'],
  };
  window.setWorkspaceView = (view, focus = false) => {
    if (!copy[view]) return;
    document.body.dataset.workspaceView = view;
    document.querySelectorAll('[data-workspace-nav]').forEach(button => {
      if (button.dataset.workspaceNav === view) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
    const [breadcrumb, heading, description] = copy[view];
    document.getElementById('workspace-location').textContent = breadcrumb;
    document.getElementById('workspace-heading').textContent = heading;
    document.getElementById('workspace-description').textContent = description;
    if (focus) { document.getElementById('workspace-heading').focus({preventScroll:true}); window.scrollTo({top:0,behavior:'instant'}); }
  };
  document.querySelectorAll('[data-workspace-nav]').forEach(button => button.addEventListener('click', () => window.setWorkspaceView(button.dataset.workspaceNav, true)));
  document.getElementById('workspace-add').addEventListener('click', () => { window.setWorkspaceView('analysis'); document.getElementById('file-input').click(); });
})();
