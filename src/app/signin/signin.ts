import { Component, inject, signal } from '@angular/core';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { NgIf, NgClass } from '@angular/common';
import { RouterLink, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-signin',
  standalone: true,
  imports: [ReactiveFormsModule, NgIf, NgClass, RouterLink],
  templateUrl: './signin.html',
  styleUrls: ['./signin.css'],
})
export class SigninComponent {
  private fb = inject(FormBuilder);
  private auth = inject(AuthService);
  private router = inject(Router);

  submitting = signal(false);
  errorMsg = signal<string | null>(null);

  form = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required]],
  });

  get f() { return this.form.controls; }

  submit() {
    this.errorMsg.set(null);
    if (this.form.invalid) { this.form.markAllAsTouched(); return; }
    this.submitting.set(true);

    this.auth.login(this.f.email.value!, this.f.password.value!).subscribe({
      next: () => {
        this.submitting.set(false);
        this.router.navigateByUrl('/dashboard');
      },
      error: (err) => {
        this.submitting.set(false);
        this.errorMsg.set(err?.error?.message || 'Login failed');
      }
    });
  }
}
