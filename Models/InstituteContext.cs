using Microsoft.EntityFrameworkCore;
using static Institute_Management.Models.CourseModule;
using static Institute_Management.Models.TeacherModule;

namespace Institute_Management.Models
{
    public class InstituteContext : DbContext
    {
        public InstituteContext(DbContextOptions<InstituteContext> options) : base(options) { }

        public DbSet<UserModule.User> Users { get; set; }
        public DbSet<StudentModule.Student> Students { get; set; }
        public DbSet<TeacherModule.Teacher> Teachers { get; set; }
        public DbSet<AdminModule.Admin> Admins { get; set; }
        public DbSet<BatchModule.Batch> Batches { get; set; }
        public DbSet<CourseModule.Course> Courses { get; set; }
        public DbSet<StudentCourseModule.StudentCourse> StudentCourses { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.Entity<BatchModule.Batch>().HasData();
            //modelBuilder.Entity<AdminModule.Admin>().HasData(); // This clears out data from Admin table
            //modelBuilder.Entity<StudentModule.Student>().HasData();
            //modelBuilder.Entity<Teacher>().HasData(); // This clears out data from Teacher table
            //modelBuilder.Entity<Course>().HasData();  // This clears out data from Course table
            //modelBuilder.Entity<StudentCourseModule.StudentCourse>().HasData();
            //modelBuilder.Entity<UserModule.User>().HasData();

            modelBuilder.Entity<Teacher>()
           .HasMany(t => t.Courses)
           .WithOne(c => c.Teacher)
           .HasForeignKey(c => c.TeacherId)
            .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<CourseModule.Course>()
            .HasOne(c => c.Teacher)
            .WithMany(t => t.Courses)
            .HasForeignKey(c => c.TeacherId)
            .OnDelete(DeleteBehavior.Cascade);


            // Configure composite primary key for StudentCourse
            modelBuilder.Entity<StudentCourseModule.StudentCourse>()
                .HasKey(sc => new { sc.StudentId, sc.CourseId });

            // Seed data
            SeedData(modelBuilder);
        }

        private void SeedData(ModelBuilder modelBuilder)
        {
            // Seeding Users first
            modelBuilder.Entity<UserModule.User>().HasData(
                new UserModule.User { UserId = 1, Name = "Admin User", Email = "admin@example.com", Password = "admin123", Role = "Admin", ContactDetails = "1234567890" },
                new UserModule.User { UserId = 2, Name = "John Doe", Email = "john@example.com", Password = "password123", Role = "Student", ContactDetails = "9876543210" },
                new UserModule.User { UserId = 3, Name = "Jane Smith", Email = "jane@example.com", Password = "teacher123", Role = "Teacher", ContactDetails = "5554443333" },
                new UserModule.User { UserId = 4, Name = "Mark Johnson", Email = "mark@example.com", Password = "teacher456", Role = "Teacher", ContactDetails = "6667778888" },
                new UserModule.User { UserId = 5, Name = "Alice Brown", Email = "alice@example.com", Password = "student123", Role = "Student", ContactDetails = "9990001111" }
            );

            // Seeding Admin (AdminUserId = 1)
            modelBuilder.Entity<AdminModule.Admin>().HasData(
                new AdminModule.Admin { AdminId = 1, UserId = 1 }
            );

            // Seeding Teachers (Ensure TeacherIds are correctly linked to UserIds)
            modelBuilder.Entity<TeacherModule.Teacher>().HasData(
                new TeacherModule.Teacher { TeacherId = 1, UserId = 3, SubjectSpecialization = "Mathematics" },
                new TeacherModule.Teacher { TeacherId = 2, UserId = 4, SubjectSpecialization = "Physics" }
            );

            // Seeding Courses (Ensure TeacherId matches existing Teachers)
            modelBuilder.Entity<CourseModule.Course>().HasData(
                new CourseModule.Course { CourseId = 1, CourseName = "Mathematics 101", Description = "Basic Mathematics", TeacherId = 1 },
                new CourseModule.Course { CourseId = 2, CourseName = "Physics 101", Description = "Fundamentals of Physics", TeacherId = 2 },
                new CourseModule.Course { CourseId = 3, CourseName = "Advanced Math", Description = "Advanced Topics in Math", TeacherId = 1 }
            );

            // Seeding Batches (Linking Courses to Batches)
            modelBuilder.Entity<BatchModule.Batch>().HasData(
                new BatchModule.Batch { BatchId = 1, BatchName = "Batch A", BatchTiming = "9:00 AM - 12:00 PM", BatchType = "Full-Time", CourseId = 1 },
                new BatchModule.Batch { BatchId = 2, BatchName = "Batch B", BatchTiming = "2:00 PM - 5:00 PM", BatchType = "Part-Time", CourseId = 2 },
                new BatchModule.Batch { BatchId = 3, BatchName = "Batch C", BatchTiming = "10:00 AM - 1:00 PM", BatchType = "Full-Time", CourseId = 3 }
            );

            // Seeding Students and linking them to Batches
            modelBuilder.Entity<StudentModule.Student>().HasData(
                new StudentModule.Student { StudentId = 1, UserId = 2, BatchId = 1 },
                new StudentModule.Student { StudentId = 2, UserId = 5, BatchId = 2 }
            );

            // Seeding Student-Course Enrollments (Many-to-Many between Students and Courses)
            modelBuilder.Entity<StudentCourseModule.StudentCourse>().HasData(
                new StudentCourseModule.StudentCourse { StudentId = 1, CourseId = 1 },
                new StudentCourseModule.StudentCourse { StudentId = 2, CourseId = 2 }
            );
        }


    }
}