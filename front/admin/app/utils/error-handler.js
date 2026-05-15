import { showToast } from '../components/ui/toast.js';

export function handleApiError(err, fallbackMessage = 'An error occurred') {
  console.error(err);
  const message = err.body?.error_description || err.body?.error || err.message || fallbackMessage;
  showToast(message, 'error');
}
