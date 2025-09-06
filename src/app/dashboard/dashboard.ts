import { Component, inject } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  template: `
    <div class="bg-white rounded-xl shadow-md p-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold mb-1">Dashboard</h1>
          <p class="text-sm text-gray-600">You are authenticated 🎉</p>
        </div>
        <button
          (click)="logout()"
          class="rounded-md bg-gray-800 text-white px-3 py-2 text-sm hover:bg-gray-900"
        >
          Logout
        </button>
      </div>
    </div>
  `
})
export class DashboardComponent {
  private auth = inject(AuthService);
  private router = inject(Router);

  logout() {
    this.auth.logout().subscribe({
      next: () => this.router.navigateByUrl('/sign-in'), // ✅ absolute
      error: () => this.router.navigateByUrl('/sign-in'),
    });
  }
}
