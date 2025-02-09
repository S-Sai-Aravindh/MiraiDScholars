using Institute_Management.DTOs;
using Institute_Management.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using static Institute_Management.Models.BatchModule;

namespace Institute_Management.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BatchController : ControllerBase
    {
        private readonly InstituteContext _context;

        public BatchController(InstituteContext context)
        {
            _context = context;
        }

        // 1. Get All Batches with related Course information
        [HttpGet]
        public async Task<IActionResult> GetAllBatches()
        {
            var batches = await _context.Batches
                .Include(b => b.Course)  // Ensure Course information is included
                .Select(b => new BatchDTO
                {
                    BatchId = (int)b.BatchId,
                    BatchName = b.BatchName,
                    BatchTiming = b.BatchTiming,
                    BatchType = b.BatchType,
                    //CourseId = b.CourseId,
                    Course = new CourseDTO  // Include related course details in the DTO
                    {
                        CourseId = (int)b.Course.CourseId,
                        CourseName = b.Course.CourseName,
                        Description = b.Course.Description
                    }
                })
                .ToListAsync();

            return Ok(batches);
        }

        // 2. Get Batch by ID with related Course information
        [HttpGet("{id}")]
        public async Task<IActionResult> GetBatchById(int id)
        {
            var batch = await _context.Batches
                .Include(b => b.Course)  // Include Course data
                .Where(b => b.BatchId == id)
                .Select(b => new BatchDTO
                {
                    BatchId = (int)b.BatchId,
                    BatchName = b.BatchName,
                    BatchTiming = b.BatchTiming,
                    BatchType = b.BatchType,
                    //CourseId = b.CourseId,
                    Course = new CourseDTO  // Include Course details in BatchDTO
                    {
                        CourseId = (int)b.Course.CourseId,
                        CourseName = b.Course.CourseName,
                        Description = b.Course.Description
                    }
                })
                .FirstOrDefaultAsync();

            if (batch == null) return NotFound();
            return Ok(batch);
        }

        // 3. Create New Batch with Course association
        [HttpPost]
        public async Task<IActionResult> CreateBatch([FromBody] BatchDTO batchDto)
        {
            if (batchDto == null)
                return BadRequest();

            //var course = await _context.Courses.FindAsync(batchDto.CourseId);
            //if (course == null)
            //    return BadRequest("Course not found");

            var batch = new Batch
            {
                BatchName = batchDto.BatchName,
                BatchTiming = batchDto.BatchTiming,
                BatchType = batchDto.BatchType,
                //CourseId = batchDto.CourseId
            };

            _context.Batches.Add(batch);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetBatchById), new { id = batch.BatchId }, batchDto);
        }

        // 4. Update Batch with Course association
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateBatch(int id, [FromBody] BatchDTO batchDto)
        {
            if (batchDto == null || id != batchDto.BatchId)
                return BadRequest();

            var batch = await _context.Batches.FindAsync(id);
            if (batch == null)
                return NotFound();

            // Ensure the course exists before updating batch
            //var course = await _context.Courses.FindAsync(batchDto.CourseId);
            //if (course == null)
            //    return BadRequest("Course not found");

            batch.BatchName = batchDto.BatchName;
            batch.BatchTiming = batchDto.BatchTiming;
            batch.BatchType = batchDto.BatchType;
            //batch.CourseId = batchDto.CourseId;

            await _context.SaveChangesAsync();

            return NoContent();
        }

        // 5. Delete Batch
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteBatch(int id)
        {
            var batch = await _context.Batches.FindAsync(id);
            if (batch == null)
                return NotFound();

            _context.Batches.Remove(batch);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    
}
}
